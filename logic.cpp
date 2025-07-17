#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>

int main(int argc, char* argv[]) {
	//argv[1] - filename
	//argv[2] - action (r or w)
	//argv[3] (optional) - text 
	if (argc < 3) {
		printf("Not enough arguments\n");
		exit(-1);
	}

	FILE* fp;

	if (strcmp(argv[2], "r") == 0) {
		fp = fopen(argv[1], "r");
		if (fp) {
			char buffer[256];

			if (fgets(buffer, 256, fp) == NULL) {
				printf("Error while reading\n");
				exit(-1);
			}
			else {
				do {
					printf("%s", buffer);
				} while ((fgets(buffer, 256, fp)) != NULL);
			}

		}
		else {
			printf("Error while opening\n");
			exit(-1);
		}
	}
	else if (strcmp(argv[2], "w") == 0 && argc >= 4) {
		fp = fopen(argv[1], "w");
		if (fp) {
			if (fputs(argv[3], fp) == EOF) {
				printf("Error while writing\n");
				exit(-1);
			}
		}
		else {
			printf("Error while opening\n");
			exit(-1);
		}
	}
	else {
		printf("Incorrect input\n");
		exit(-1);
	}
	printf("\nSuccess\n");
	fclose(fp);
}