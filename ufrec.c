#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include"pbkdf2_extract.h"

/*
For handling any error that are arised during decryption
*/
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
This function carries out the AES 256 decryption
*/
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int main(int argc, char *argv[]){

    struct sockaddr_in server_address;
    int server_address_size = sizeof(server_address);
    int socket_id, new_socket;
    char buff[4096];

    unsigned char *decryptedtext = NULL;
    unsigned char *iv_read = malloc(16);
    unsigned char *tag_read = malloc(16);
    unsigned char *cipher_read = NULL;
    unsigned char *file_size_char = malloc(sizeof(long));
    long rest_of_file_size = 0;
    int decryptedtext_len;
    size_t iv_len = 16;

    FILE *file_pointer;

    unsigned char* key_ret;

    char password[100];
    int n=0;

    int local = 0;
    /*
    if local is 0 then that means -d is selected (Send to a port number on the specified ip addr)
    if local is 1 then -l is the given input. (Run Locally)
    */
   char *port_input;
   int port_no;

    if(argc < 3){
        printf("Insuffiecient number of outputs");
        return 0;
    }

    local = strcmp(argv[2], "-d");

     /* if we are using -d(dumps) mode then we need the 
     port number to bind the connection 
    */
    if(argc == 4 && local == 0 ){
        port_no = atoi(argv[3]);
    }

    /*
    If we are -dumps mode then we need to bind to a port and then wait for connections
    this is carried out here
    */
    if(local == 0){
        socket_id = socket(AF_INET, SOCK_STREAM, 0);
        if(socket_id == -1){
            printf("Socket Creation: Status - Failed \n");
        }
        // else{
        //     printf("Socket Created Successfully \n");
        // }

        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = htonl(INADDR_ANY);
        server_address.sin_port = htons(8080);

        if((bind(socket_id, (struct sockaddr*)&server_address, sizeof(server_address))) != 0 ){
            printf("Socket Bind: Status Failed \n");
        }
        // else{
        //     printf("Socket Bind: Status Success \n");
        // }

        if((listen(socket_id, 5)) != 0){
            printf("Socket Listen: Status Failed \n");
        }
        else{
            printf("Waiting for Connections \n");
        }

        new_socket = accept(socket_id, (struct sockaddr*)&server_address, &server_address_size);
        if(new_socket < 0){
            printf("Server Acceptance: Status Failed");
        }
        else{
            printf("Inbound File \n");
        }
    }
   
    /*
   Collect the user password to generate a Key using PBKDF2.
   */ 

    printf("Password:");
    while ((password[n++] = getchar()) != '\n')
        ;

    // Key that has been returned from the function
    key_ret = get_key_using_pbkdf2(password);

    /*
    read the iv, size of the encrypted text and tag from ufsend in -d mode.
    or else use the input file name and read the file data and split the IV,
    encrypted text and TAG data
    */

    if(local == 0){
        read(new_socket, iv_read, 16);
        read(new_socket, file_size_char, 8);
        rest_of_file_size = (long)atoi((char *)file_size_char);
        cipher_read = malloc(rest_of_file_size);
        read(new_socket, cipher_read, rest_of_file_size);
        read(new_socket, tag_read, 16);
    }
    else{

        file_pointer = fopen(argv[1], "rb");

        if(file_pointer != NULL){
            fseek(file_pointer, 0L, SEEK_SET);
            size_t read_iv = fread(iv_read, sizeof(char), 16, file_pointer);
            fseek(file_pointer, 0L, SEEK_SET);
            fseek(file_pointer, -16L, SEEK_END);
            rest_of_file_size = (sizeof(char) * (ftell(file_pointer)) ) - 16;
            // printf("The read file size is: %ld", rest_of_file_size);
            cipher_read = malloc(rest_of_file_size);
            fseek(file_pointer, 16L, SEEK_SET);
            size_t read_cipher = fread(cipher_read, sizeof(char), rest_of_file_size, file_pointer);
            // printf("\nprinting out the read cipher: \n");
            // BIO_dump_fp (stdout, (const char *)cipher_read, read_cipher);
            fseek(file_pointer, -16L, SEEK_END);
            size_t read_tag = fread(tag_read, sizeof(char), 16, file_pointer);
            // printf("The read IV is: %s", iv_read);
            // printf("The cipher text read is: %s", cipher_read);
            // printf("The tag read is: %s", tag_read);
        }

        fclose(file_pointer);

    }

    /*
    Print the recieved encrypted file
    */
    printf("Recieved Cipher is: \n");
    BIO_dump_fp (stdout, (const char *)cipher_read, rest_of_file_size);

    /*using the given data decrypt the file and print the result if it is successful*/
    decryptedtext = malloc(rest_of_file_size + 16 );
    decryptedtext_len = gcm_decrypt(
                                cipher_read, 
                                rest_of_file_size,
                                tag_read,
                                key_ret, 
                                iv_read, 
                                iv_len,
                                decryptedtext
                                );

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
        printf("Successfully recieved encrypted file and decrypted the text. %ld bytes written", rest_of_file_size);
    } else {
        printf("Decryption failed: Not the Expected output\n");
    }

    //write decrypted plain text to a new file
    if(local == 0){
        if( access( argv[1], F_OK) == 0 ){
            printf("\n Output file already exists try again with a different name or deleting the file \n");
            return 33;
        }
        file_pointer = fopen(argv[1], "wb");
    }else{
        argv[1][strlen(argv[1]) - 6 ] = '\0';
        if( access( argv[1], F_OK) == 0 ){
            printf("\n Output file already exists try again with a different name or deleting the file \n");
            return 33;
        }
        file_pointer = fopen(argv[1], "wb");
    }
    fwrite(decryptedtext, sizeof(char), rest_of_file_size, file_pointer);
    fclose(file_pointer);


    return 0;
}
