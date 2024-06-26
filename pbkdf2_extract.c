#include"pbkdf2_extract.h"


/*
This function uses the inbuilt PKCS5_PBKDF2_HMAC function provided by openssl
to carry out the PBKDF2 implementation and return the KEY.
*/

unsigned char* get_key_using_pbkdf2(char *password ){
    static unsigned char derived[32];
    int iterations = 4096;
    int r;
    int password_length = 0;
    int salt_length = 14;

    const EVP_MD *hash_id = EVP_get_digestbyname("sha3-256");
    

    for(int i=0; password[i] != '\n'; i++){
        if(password[i]!=' ')
        {
            password_length++;
        }
    }

    r = PKCS5_PBKDF2_HMAC(
        password, 
        (int)password_length, 
        (const unsigned char *)"SodiumChloride",
		(int)salt_length, 
        iterations, 
        hash_id, 
        (int)sizeof(derived), 
        (unsigned char*) derived);

    const unsigned char *key = derived+0;
    
    printf("Key: ");
    for (size_t i=0; i<32; ++i)
        printf("%02x ", key[i]);
    printf("\n");

    return derived;

}