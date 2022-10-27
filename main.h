
#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gcrypt.h>

typedef struct {
	uint8_t* text;
	uint8_t* cipher;
	uint8_t text_size;
	uint8_t cipher_size;
} cipher_stream, *pcipher_stream;

static unsigned short verbose, key_save_file = 1;
