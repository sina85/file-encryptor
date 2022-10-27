#include "asymmetric.h"

void show_sexp(const char *prefix, gcry_sexp_t a) {
	char *buf;
	size_t size;

	if(prefix) fputs(prefix, stderr);
	size = gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	buf = gcry_xmalloc (size);

	gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, buf, size);
	fprintf(stderr, "%.*s", (int)size, buf);
	gcry_free (buf);
}
//initialize a new sexpression containing the public key pair
gcry_error_t asymmetric_init(gcry_sexp_t* pkey, gcry_sexp_t* skey, char* file_key_path) {
	gcry_sexp_t pub_key, sec_key, key, key_spec;
	gcry_error_t err_t = 0;

	if(file_key_path == NULL) {
		err_t = gcry_sexp_new(&key_spec, "(genkey (rsa (nbits 4:1024)))", 0, 1);
		if(err_t) {
			printf("Error! creating S-expression: %s\n", gcry_strerror(err_t));
			goto end;
		}
		err_t = gcry_pk_genkey(&key, key_spec);
		if(err_t) {
			printf("Error! generating RSA: %s\n", gcry_strerror(err_t));
			goto end;
		}

		pub_key = gcry_sexp_find_token(key, "public-key", 0);
		if(!pub_key) {
			puts("public part missing in key\n");
			goto end;
		}

		sec_key = gcry_sexp_find_token(key, "private-key", 0);
		if(!sec_key) {
			puts("private part missing in key\n");
			goto end;
		}
	}
	else {

	}
	*pkey = pub_key;
	*skey = sec_key;
end:
	gcry_sexp_release (key);
	gcry_sexp_release(key_spec);
	return 0;
}
gcry_error_t asymmetric_encrypt(gcry_sexp_t pkey, pcipher_stream str) {
	gcry_sexp_t plain, cipher;
	gcry_error_t err_t;

	err_t = gcry_sexp_build(&plain, NULL, "(data (flags oaep) (value %s))", str->text);
	if(err_t) {
		printf("Error! generating S-expression for encryption: %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
		return err_t;
	}
	
	gcry_pk_encrypt(&cipher, plain, pkey);
	gcry_sexp_release(plain);
	if(err_t) {
		printf("Error! encrypting failed: %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
		return err_t;
	}

	show_sexp(NULL, cipher);

	return err_t;
}
gcry_error_t asymmetric_decrypt(gcry_sexp_t skey, pcipher_stream str) {
	gcry_sexp_t plain, cipher;
    gcry_error_t err_t;

    err_t = gcry_sexp_build(&cipher, NULL, "(data (flags oaep) (value %s))", str->cipher);
    if(err_t) {
        printf("Error! generating S-expression for decryption: %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
        return err_t;
    }

    gcry_pk_decrypt(&plain, cipher, skey);
    gcry_sexp_release(plain);
    if(err_t) {
        printf("Error! encrypting failed: %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
        return err_t;
    }

    show_sexp(NULL, cipher);

    return err_t;
}
gcry_error_t handle_asymmetric_operation(
	char* file_skey_path, char* file_in_path, 
	char* file_out_path, unsigned short en)
{
	gcry_error_t err_t = 0;
	FILE* file_in = NULL, *file_out = NULL, *wfile_key = NULL;
	long file_in_size = 0, skey_save_size = 0, pkey_save_size = 0;
	cipher_stream stream = { 0 };
	gcry_sexp_t pkey, skey; 
	char *skey_save = NULL, *pkey_save = NULL;
	
	err_t = asymmetric_init(&pkey, &skey);
	if(err_t) {
		printf("Error! Asymmetric initialization failed! %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
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

	if(en) err_t = asymmetric_encrypt(pkey, &stream);
	else err_t = asymmetric_decrypt(skey, &stream);

	if(err_t) {
		printf("Error! Asymmetric encryption failed! %s/%s\n", gcry_strsource(err_t), gcry_strerror(err_t));
		goto end;
	}

	fwrite(stream.cipher, stream.cipher_size, 1, file_out);
	fclose(file_out);
	
	if(verbose) print_hex(&sym_key);
	
	if(key_save_file) {
		wfile_key = fopen("asymmetric.key", "w");
		skey_save_size = gcry_sexp_sprint(skey, GCRYSEXP_FMT_DEFAULT, NULL, 0);
		skey_save = (char*)malloc(skey_save_size);
		if(gcry_sexp_sprint(skey, GCRYSEXP_FMT_DEFAULT, skey_save, skey_save_size) == NULL) {
			puts("Error! Failed to save Asymmetric key to file\n");
			goto end;
		}
		fwrite(skey_save, skey_save_size, 1, wfile_key);
		


		fwrite(sym_key->counter, sym_key->block_len, 1, wfile_key);
		fclose(wfile_key);
	}
end:
	if(stream.text) free(stream.text);
	if(stream.cipher) free(stream.cipher);
	if(skey_save) free(skey_save);
	if(pkey_save) free(pkey_save);
	return err_t;
}