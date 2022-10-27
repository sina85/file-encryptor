#include "symmetric.h"
#include "asymmetric.h"

int main(int argc, char** argv) {
	gcry_error_t err_t = 0;
	key_block sym_key = { 0 };
	unsigned short sym_type = 0, en = 0;
	char *file_in_path = NULL, *file_out_path = NULL, 
	*file_skey_path = NULL, *file_akey_path = NULL, *var;

	if(argc < 2) {
help:
		printf("\nusage: %s <OPTIONS>", argv[0]);
		puts("\nOPTIONS ->\n");
		puts("-i\tfile input\n-o\tfile output");
		puts("-e\tencrypt\n-d\tdecrypt\n");
		puts("-t\tencryption type (sym OR asym)");
		puts("-ra\tread assymetric key from file location");
		puts("-rs\tread symetric key from file location");
		puts("-v\tverbose");
		puts("-n\tdon't write key to file\n!WARNING!\
		File contents can not be restored without the key\n");
		goto end;
	}

	for(int i = 1; i < argc; ++i) { // remove space
		if(strchr(argv[i], '\'')) continue;
		if(var = strchr(argv[i], ' ')) {
			while(var = strchr(argv[i], ' '))
				memcpy(var, var + 1, strlen(var));
		}
	}
	
	for(int i = 1; i < argc; ++i) {
		if(memcmp(argv[i], "-i", 2) == 0) {
			file_in_path = (char*)malloc(strlen(&argv[i][2]) + 1);
			memcpy(file_in_path, &argv[i][2], strlen(&argv[i][2]) + 1);
		}
		else if(memcmp(argv[i], "-o", 2) == 0) {
			file_out_path = (char*)malloc(strlen(&argv[i][2]) + 1);
			memcpy(file_out_path, &argv[i][2], strlen(&argv[i][2]) + 1);
		}
		else if(memcmp(argv[i], "-tsym", 5) == 0) sym_type = 1;
		else if(memcmp(argv[i], "-tasym", 5) == 0) sym_type = 0;
		else if(memcmp(argv[i], "-e", 2) == 0) en = 1;
		else if(memcmp(argv[i], "-d", 2) == 0) en = 0;
		else if(memcmp(argv[i], "-rs", 3) == 0) {
			file_skey_path = (char*)malloc(strlen(&argv[i][3]) + 1);
			memcpy(file_skey_path, &argv[i][3], strlen(&argv[i][3]) + 1);
		}
		else if(memcmp(argv[i], "-ra", 3) == 0) {
			file_akey_path = (char*)malloc(strlen(&argv[i][3]) + 1);
			memcpy(file_akey_path, &argv[i][3], strlen(&argv[i][3]) + 1);
		}
		if(memcmp(argv[i], "-n", 2) == 0) key_save_file = 0;
	}

	if(file_in_path == NULL) goto help;

	if(sym_type) {
		err_t = handle_operation_symmetric(&sym_key, file_skey_path, file_in_path, file_out_path, en);	
		if(err_t) goto end;
	}
	else {
		err_t = handle_asymmetric_operation(file_skey_path, file_in_path, file_out_path, en);
	}

	if(file_in_path) free(file_in_path);
	if(file_out_path) free(file_out_path);
	if(file_skey_path) free(file_skey_path);
	if(file_akey_path) free(file_akey_path);
	symmetric_terminate(&sym_key);
	return 0;
end:
	if(file_in_path) free(file_in_path);
	if(file_out_path) free(file_out_path);
	if(file_skey_path) free(file_skey_path);
	if(file_akey_path) free(file_akey_path);
	symmetric_terminate(&sym_key);
	return 1;
}