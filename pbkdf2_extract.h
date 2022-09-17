#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#ifndef pbkdf2_extract_h
#define pbkdf2_extract_h

unsigned char* get_key_using_pbkdf2(char *password);

#endif