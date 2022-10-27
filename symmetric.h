#pragma once
#include "main.h"

typedef struct {
	gcry_cipher_hd_t handle;
	uint8_t* key;
	uint8_t* salt;
	uint8_t* counter;
	uint8_t key_len;
	uint8_t block_len;
} key_block, *pkey_block;

gcry_error_t symmetric_encrypt(pkey_block, pcipher_stream);
gcry_error_t symmetric_decrypt(pkey_block, pcipher_stream);
gcry_error_t symmetric_init(pkey_block, char*);
void symmetric_terminate(pkey_block);
gcry_error_t handle_operation_symmetric( 
	pkey_block sym_key, char* file_skey_path, 
	char* file_in_path, char* file_out_path,
	unsigned short en);
void print_hex(pkey_block);