/*++

Module Name:

    DriverFilter.c

Abstract:

    This is the main module of the DriverFilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltkernel.h>
#include <dontuse.h>
#include <suppress.h>

#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME gGetProcessImageFileName;

#define MAX_GROUPS 5
#define  MAX_ENTERIES 10
#define  MAX_NAME 64

typedef struct Group {
    char name[MAX_NAME];
    char processes[MAX_ENTERIES][MAX_NAME];
    int countProc;
    char denyWrite[MAX_ENTERIES][MAX_NAME];
    int countWD;
    char denyRead[MAX_ENTERIES][MAX_NAME];
    int countRD;
}Group;
int counter;
int flag;
Group groups[MAX_GROUPS];

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
DriverFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
DriverFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
DriverFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
DriverFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
DriverFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
DriverFilterOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
DriverFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
DriverFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
DriverFilterInstanceQueryTeardownNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
DriverFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverFilterUnload)
#pragma alloc_text(PAGE, DriverFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, DriverFilterInstanceSetup)
#pragma alloc_text(PAGE, DriverFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, DriverFilterInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      DriverFilterOperationPassThrough,
      DriverFilterPostOperation },

    { IRP_MJ_READ,
      0,
      DriverFilterOperationPassThrough,
      DriverFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      DriverFilterOperationPassThrough,
      DriverFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      DriverFilterOperationPassThrough,
      DriverFilterPostOperation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    DriverFilterUnload,                           //  MiniFilterUnload

    DriverFilterInstanceSetup,                    //  InstanceSetup
    DriverFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    DriverFilterInstanceTeardownStart,            //  InstanceTeardownStart
    DriverFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
DriverFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}


NTSTATUS
DriverFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}


VOID
DriverFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterInstanceTeardownStart: Entered\n"));
}


VOID
DriverFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterInstanceTeardownComplete: Entered\n"));
}

void parseDeny() {

    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;

    //opening file with deny
    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\deny.txt");
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE   handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK    ioStatusBlock;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    LARGE_INTEGER      byteOffset;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_READ,
        &objAttr, &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    
    //start reading
#define  BUFFER_SIZE 1024

    CHAR buffer[BUFFER_SIZE] = { '\0' };

    if (NT_SUCCESS(ntstatus)) {
        byteOffset.LowPart = byteOffset.HighPart = 0;
        ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
            buffer, BUFFER_SIZE, &byteOffset, NULL);
        if (NT_SUCCESS(ntstatus)) {
            //parsing <group> <dir> <action>
            char dirPath[MAX_NAME] = { '\0' };
            char action[6] = { '\0' };
            //parsing
            int i = 0, j = 0;
            char groupName[MAX_NAME] = { '\0' };

            while (buffer[i] != '\0') {

                //group name
                for (j = 0; buffer[i] != ' '; i++, j++)
                    groupName[j] = buffer[i];
                for (; j < MAX_NAME; j++) groupName[j] = '\0';
                i++;
                //dir
                for (j = 0; buffer[i] != ' '; i++, j++)
                    dirPath[j] = buffer[i];
                for (; j < MAX_NAME; j++) dirPath[j] = '\0';
                i++;

                //action
                for (j = 0; buffer[i] != '\n' && buffer[i] != '\0'; i++, j++)
                    action[j] = buffer[i];
                for (; j < 6; j++) action[j] = '\0';
                i++;

                for (j = 0; j < counter; j++) { //search for group
                    if (strstr(groups[j].name, groupName)) {
                        if (strstr(action, "write")) {
                            strcpy(groups[j].denyWrite[groups[j].countWD], dirPath);
                            groups[j].countWD += 1;
                        }
                        else if (strstr(action, "read")) {
                            strcpy(groups[j].denyRead[groups[j].countRD], dirPath);
                            groups[j].countRD += 1;
                        }
                        break;
                    }
                }

                if (buffer[i - 1] == '\0') break;
            }
        }
        ZwClose(handle);
    }
}

void parseGroups() {

    //opening file with groups
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\groups.txt");
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE   handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK    ioStatusBlock;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    LARGE_INTEGER      byteOffset;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_READ,
        &objAttr, &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    //start reading
#define  BUFFER_SIZE 1024

    CHAR buffer[BUFFER_SIZE] = { '\0' };

    if (NT_SUCCESS(ntstatus)) {
        flag = 0;
        byteOffset.LowPart = byteOffset.HighPart = 0;
        ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
            buffer, BUFFER_SIZE, &byteOffset, NULL);

        if (NT_SUCCESS(ntstatus)) {
            //parsing
            int i = 0, j = 0;
            char procName[MAX_NAME] = { '\0' }, groupName[MAX_NAME] = { '\0' };
            for (j = 0; j < counter; j++) {
                groups[j].countProc = 0;
                groups[j].countWD = 0;
                groups[j].countRD = 0;
            }
            counter = 0;

            while (buffer[i] != '\0') {

                //process name
                for (j = 0; buffer[i] != ' '; i++, j++)
                    procName[j] = buffer[i];
                for (; j < MAX_NAME; j++) procName[j] = '\0';
                i++;

                //group name
                for (j = 0; buffer[i] != '\n' && buffer[i] != '\0'; i++, j++)
                    groupName[j] = buffer[i];
                for (; j < MAX_NAME; j++) groupName[j] = '\0';
                i++;


                //add process to exist group
                for (j = 0; j < counter; j++) {
                    if (strstr(groups[j].name, groupName)) {
                        strcpy(groups[j].processes[groups[j].countProc], procName);
                        groups[j].countProc += 1;
                        break;
                    }
                }
                //create new group
                if (j == counter) {
                    strcpy(groups[counter].name, groupName);
                    strcpy(groups[counter].processes[groups[counter].countProc], procName);
                    groups[counter].countProc += 1;
                    counter++;
                }

                if (buffer[i - 1] == '\0') break;
            }
        }
        ZwClose(handle);
        parseDeny();
    }
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverEntry: Entered\n"));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status)) {

            FltUnregisterFilter(gFilterHandle);
        }
    }
   
    UNICODE_STRING sPsGetProcessImageFileName = RTL_CONSTANT_STRING(
        L"PsGetProcessImageFileName");
    gGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)
        MmGetSystemRoutineAddress(&sPsGetProcessImageFileName);

    parseGroups();

    DbgPrint("Groups:");
    int j = 0, i = 0;

    for (j = 0; j < counter; j++) {
        DbgPrint("%s ", groups[j].name);

        for (i = 0; i < groups[j].countProc; i++) {
            DbgPrint("%s ", groups[j].processes[i]);
        }

        DbgPrint("write:");
        for (i = 0; i < groups[j].countWD; i++) {
            DbgPrint("%s ", groups[j].denyWrite[i]);
        }

        DbgPrint("read:");
        for (i = 0; i < groups[j].countRD; i++) {
            DbgPrint("%s ", groups[j].denyRead[i]);
        }
    }

    return status;
}

NTSTATUS
DriverFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterUnload: Entered\n"));

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}


int checkAccess(int groupNum, int action, char* filename) {
    int i = 0;
    if (action == IRP_MJ_WRITE || action == IRP_MJ_CREATE) {
        for (; i < groups[groupNum].countWD; i++) {
            if (strstr(filename, groups[groupNum].denyWrite[i])) {
                DbgPrint("deny write to %s", filename);
                return 0;
            }
        }
    }
    else if (action == IRP_MJ_READ) {
        for (; i < groups[groupNum].countRD; i++) {
            if (strstr(filename, groups[groupNum].denyRead[i])) {
                DbgPrint("deny read %s", filename);
                return 0;
            }
        }
    }

    return 1;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS  //pre proc
DriverFilterOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterOperationPassThrough: Entered\n"));

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (DriverFilterDoRequestOperationStatus(Data)) {

        status = FltRequestOperationStatusCallback(Data,
            DriverFilterOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("DriverFilter!DriverFilterOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }

    //data хранит данные по текущей операции ввода/вывода
    if (Data->Iopb->TargetFileObject->FileName.Length > 0)
    {
        ACCESS_MASK desA = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        char filename[MAX_NAME];
        if (Data->Iopb->MajorFunction == IRP_MJ_WRITE || Data->Iopb->MajorFunction == IRP_MJ_READ || 
            (Data->Iopb->MajorFunction == IRP_MJ_CREATE && ((desA & FILE_WRITE_DATA) || (desA & FILE_APPEND_DATA))))
        {
            //getting proccess name
            PEPROCESS peprocess;
            char* processName;
            
            wcstombs(filename, Data->Iopb->TargetFileObject->FileName.Buffer, MAX_NAME);

            HANDLE pid = PsGetCurrentProcessId();
            status = PsLookupProcessByProcessId(pid, &peprocess);
            if ((!NT_SUCCESS(status)) || (!peprocess))
            {
                return FALSE;
            }
            processName = (CHAR*)gGetProcessImageFileName(peprocess);
            
            if (Data->Iopb->MajorFunction == IRP_MJ_WRITE && (strstr(filename, "\\Windows\\deny.txt") ||
                strstr(filename, "\\Windows\\groups.txt")))
                flag = 1;

            int i = 0, j = 0;
            for (; i < MAX_GROUPS; i++) {
                for (j = 0; j < groups[i].countProc; j++) {
                    if (strcmp(processName, groups[i].processes[j]) == 0) {
                        DbgPrint("find in group %s process name: %s", groups[i].name, groups[i].processes[j]);

                        if (!checkAccess(i, Data->Iopb->MajorFunction, filename)) {
                            return FLT_PREOP_DISALLOW_FASTIO;
                        }
                        else {
                            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
                        }
                    }
                }
            }
        }   
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
DriverFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
)
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
        ("DriverFilter!DriverFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
            OperationStatus,
            RequesterContext,
            ParameterSnapshot->MajorFunction,
            ParameterSnapshot->MinorFunction,
            FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
DriverFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterPostOperation: Entered\n"));

    if (Data->Iopb->TargetFileObject->FileName.Length > 0)
    {
        if (Data->Iopb->MajorFunction == IRP_MJ_CLOSE)
        {
            char filename[MAX_NAME];
            wcstombs(filename, Data->Iopb->TargetFileObject->FileName.Buffer, MAX_NAME);
            
            if ((strstr(filename, "\\Windows\\deny.txt") || strstr(filename, "\\Windows\\groups.txt")) && flag == 1){
                int j = 0, i = 0;
                flag = 0;
                parseGroups();

                DbgPrint("\nGroups:");

                for (j = 0; j < counter; j++) {
                    DbgPrint("%s ", groups[j].name);

                    for (i = 0; i < groups[j].countProc; i++) {
                        DbgPrint("%s ", groups[j].processes[i]);
                    }

                    DbgPrint("write:");
                    for (i = 0; i < groups[j].countWD; i++) {
                        DbgPrint("%s ", groups[j].denyWrite[i]);
                    }

                    DbgPrint("read:");
                    for (i = 0; i < groups[j].countRD; i++) {
                        DbgPrint("%s ", groups[j].denyRead[i]);
                    }
                }
            }
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
DriverFilterInstanceQueryTeardownNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DriverFilter!DriverFilterInstanceQueryTeardownNoPostOperation: Entered\n"));

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
DriverFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

        //
        //  Check for oplock operations
        //

        (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
            ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

            ||

            //
            //    Check for directy change notification
            //

            ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
                (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
            );
}
