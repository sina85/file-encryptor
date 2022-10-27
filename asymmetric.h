#pragma once
#include "main.h"

#include "asymmetric.h"

void show_sexp(const char *prefix, gcry_sexp_t a);

//initialize a new sexpression containing the public key pair
gcry_error_t asymmetric_init(gcry_sexp_t* pkey, gcry_sexp_t* skey);

gcry_error_t asymmetric_encrypt(gcry_sexp_t pkey, pcipher_stream str);

gcry_error_t asymmetric_decrypt(gcry_sexp_t skey, pcipher_stream str);
//handle the operation as user specified
gcry_error_t handle_asymmetric_operation(
	char* file_skey_path, char* file_in_path, 
	char* file_out_path, unsigned short en);