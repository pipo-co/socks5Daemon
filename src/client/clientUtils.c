#include "client/clientUtils.h"
#include "client/clientDefs.h"

#include <stdlib.h>     // NULL
#include <stdio.h>      // fgets
#include <string.h>     // strchr

uint64_t client_read_uint(char *message, uint64_t max){
	
	char * end;
	char num[UINT64_BASE_10_SIZE];
	uint64_t num64;
	int c;

	do {
		printf("%s", message);
		
		fgets(num, UINT64_BASE_10_SIZE, stdin);
		end = strchr(num, '\n');
		
		if(end == NULL){
			while ((c = getchar()) != '\n' && c != EOF);
		}
		
		end = NULL;
		num64 = strtoul(num, &end, 10);

	} while(end == num && num64 >= max);

	return num64;
}

uint64_t client_read_uint_or_char(char *message, uint64_t max, char * firstChar, bool *isUint){
	
	char * end;
	char num[UINT64_BASE_10_SIZE];
	uint64_t num64;
	int c;
	*isUint = true;
	*firstChar = '\0';
	do {
		printf("%s", message);
		
		fgets(num, UINT64_BASE_10_SIZE, stdin);
		end = strchr(num, '\n');

		if(end == NULL){
			while ((c = getchar()) != '\n' && c != EOF);
		}
		
		end = NULL;
		num64 = strtoul(num, &end, 10);

		if(end == num){
			*firstChar = *end;
			*isUint = false;
			return 0;
		}


	} while(end == num && num64 >= max);

	return num64;
}
