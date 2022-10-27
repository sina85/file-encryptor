#include "symmetric.h"


void print_hex(pkey_block key_info) {
	puts("\n----------------------");
	puts("KEY ->\n");
	for(int i = 0 ; i < key_info->key_len; ++i) printf("%hhX ", ((char*)key_info->key)[i]);
	puts("\nSALT ->");
	for(int i = 0 ; i < key_info->block_len; ++i) printf("%hhX ", ((char*)key_info->salt)[i]);
	puts("\nCOUNTER ->");
	for(int i = 0 ; i < key_info->block_len; ++i) printf("%hhX ", ((char*)key_info->counter)[i]);
	puts("\n----------------------");
}

gcry_error_t symmetric_encrypt(pkey_block key_info, pcipher_stream str) {
	gcry_error_t err_t = 0;
	
	err_t = gcry_cipher_encrypt(key_info->handle, str->cipher, str->cipher_size, str->text, str->text_size);

	return err_t;
}
gcry_error_t symmetric_decrypt(pkey_block key_info, pcipher_stream str) {
	gcry_error_t err_t = 0;
	
	err_t = gcry_cipher_decrypt(key_info->handle, str->cipher, str->cipher_size, str->text, str->text_size);
	
	return err_t;
}
gcry_error_t symmetric_init(pkey_block key_info, char* skey_path) {
	gcry_error_t err_t = 0;
	FILE* skey = NULL;

	if (!gcry_check_version (GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt is too old (need %s, have %s)\n", GCRYPT_VERSION, gcry_check_version(NULL));
		exit (2);
	}

	if (key_info == NULL) key_info = (pkey_block)malloc(sizeof(key_block));

	err_t = gcry_cipher_open(&key_info->handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
	if (err_t) return err_t;

	key_info->key_len = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	key_info->block_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);

	if(skey_path) {
		skey = fopen(skey_path, "r");
		if(skey == NULL) {
			printf("can not open file %s for reading symmetric key\n", skey_path);
			return 0;
		}
		key_info->key = malloc(key_info->key_len);
		fread(key_info->key, key_info->key_len, 1, skey);

		key_info->salt = malloc(key_info->block_len);
		fread(key_info->salt, key_info->block_len, 1, skey);

		key_info->counter = malloc(key_info->block_len);
		fread(key_info->counter, key_info->block_len, 1, skey);
	}
	else {
		key_info->key = gcry_random_bytes(key_info->key_len, GCRY_VERY_STRONG_RANDOM);
		key_info->salt = gcry_random_bytes(key_info->block_len, GCRY_STRONG_RANDOM);
		key_info->counter = gcry_random_bytes(key_info->block_len, GCRY_STRONG_RANDOM);	
	}
	err_t = gcry_cipher_setkey(key_info->handle, key_info->key, key_info->key_len);
	if (err_t) return err_t;

	err_t = gcry_cipher_setiv(key_info->handle, key_info->salt, key_info->block_len);
	if (err_t) return err_t;
	
	err_t = gcry_cipher_setctr(key_info->handle, key_info->counter, key_info->block_len);
	if (err_t) return err_t;

	return 0;
}
gcry_error_t handle_operation_symmetric( 
	pkey_block sym_key, char* file_skey_path, 
	char* file_in_path, char* file_out_path,
	unsigned short en)
{
	gcry_error_t err_t = 0;
	FILE* file_in = NULL, *file_out = NULL, *wfile_key = NULL;
	long file_in_size = 0;
	cipher_stream stream = { 0 };
	
	err_t = symmetric_init(sym_key, file_skey_path);
	if(err_t) {
		printf("Error! Symmetric initialization failed! %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
		goto end;
	}
	file_in = fopen(file_in_path, "r");
	fseek(file_in, 0, SEEK_END);
	file_in_size = ftell(file_in);
	rewind(file_in);

	stream.text_size = file_in_size;
	stream.text = malloc(stream.text_size);
	stream.cipher = malloc(stream.text_size);
	stream.cipher_size = stream.text_size;

	if(file_out_path == NULL) {
		file_out_path = malloc(16);
		memcpy(file_out_path, "file.out", 9);
	}

	fread(stream.text, file_in_size, 1, file_in);
	fclose(file_in);

	file_out = fopen(file_out_path, "w");
	if(file_out == NULL) {
		printf("failed to create output file in -> %s\n", file_out_path);
		goto end;
	}

	if(en) err_t = symmetric_encrypt(sym_key, &stream);
	else err_t = symmetric_decrypt(sym_key, &stream);

	if(err_t) {
		printf("Error! Symmetric encryption failed! %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
		goto end;
	}

	fwrite(stream.cipher, stream.cipher_size, 1, file_out);
	fclose(file_out);

	if(verbose) print_hex(sym_key);
	
	if(key_save_file) {
		wfile_key = fopen("symmetric.key", "w");
		fwrite(sym_key->key, sym_key->key_len, 1, wfile_key);
		fwrite(sym_key->salt, sym_key->block_len, 1, wfile_key);
		fwrite(sym_key->counter, sym_key->block_len, 1, wfile_key);
		fclose(wfile_key);
	}
end:
	if(stream.text) free(stream.text);
	if(stream.cipher) free(stream.cipher);
	return err_t;
}
void symmetric_terminate(pkey_block key_info) {
	if(key_info) {
		gcry_cipher_close(key_info->handle);
		free(key_info->key);
		free(key_info->salt);
		free(key_info->counter);
	}
}