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

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

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

    if(argc == 4 && local == 0 ){
        port_no = atoi(argv[3]);
        printf("This is port %d", port_no);
    }

    if(local == 0){
        socket_id = socket(AF_INET, SOCK_STREAM, 0);
        if(socket_id == -1){
            printf("Socket Creation: Status - Failed \n");
        }
        else{
            printf("Socket Created Successfully \n");
        }

        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = htonl(INADDR_ANY);
        server_address.sin_port = htons(8080);

        if((bind(socket_id, (struct sockaddr*)&server_address, sizeof(server_address))) != 0 ){
            printf("Socket Bind: Status Failed \n");
        }else{
            printf("Socket Bind: Status Success \n");
        }

        if((listen(socket_id, 5)) != 0){
            printf("Socket Listen: Status Failed \n");
        }else{
            printf("Socket Listen: Status Success \n");
        }

        new_socket = accept(socket_id, (struct sockaddr*)&server_address, &server_address_size);
        if(new_socket < 0){
            printf("Server Acceptance: Status Failed");
        }
        else{
            printf("Server Acceptance: Status Accepted");
        }
    }
   
    

    printf("Password:");
    while ((password[n++] = getchar()) != '\n')
        ;

    // Key that has been returned from the function
    key_ret = get_key_using_pbkdf2(password);

    if(local == 0){
        printf("waiting here");
        read(new_socket, iv_read, 16);
        printf("The read IV is: %s", iv_read);
        read(new_socket, file_size_char, 8);
        printf("\nThe cipher text size read is: %s \n", file_size_char);
        rest_of_file_size = (long)atoi((char *)file_size_char);
        cipher_read = malloc(rest_of_file_size);
        read(new_socket, cipher_read, 1151);
        printf("The cipher text read is: %s", cipher_read);
        printf("The cipher text size read is: %ld", (long)rest_of_file_size);
        read(new_socket, tag_read, 16);
        printf("The tag read is: %s", tag_read);
    }
    else{

        file_pointer = fopen(argv[1], "rb");

        if(file_pointer != NULL){
            fseek(file_pointer, 0L, SEEK_SET);
            size_t read_iv = fread(iv_read, sizeof(char), 16, file_pointer);
            fseek(file_pointer, 0L, SEEK_SET);
            fseek(file_pointer, -16L, SEEK_END);
            rest_of_file_size = (sizeof(char) * (ftell(file_pointer)) ) - 16;
            printf("The read file size is: %ld", rest_of_file_size);
            cipher_read = malloc(rest_of_file_size);
            fseek(file_pointer, 16L, SEEK_SET);
            size_t read_cipher = fread(cipher_read, sizeof(char), rest_of_file_size, file_pointer);
            printf("\nprinting out the read cipher: \n");
            // BIO_dump_fp (stdout, (const char *)cipher_read, read_cipher);
            fseek(file_pointer, -16L, SEEK_END);
            size_t read_tag = fread(tag_read, sizeof(char), 16, file_pointer);
            printf("The read IV is: %s", iv_read);
            printf("The cipher text read is: %s", cipher_read);
            printf("The tag read is: %s", tag_read);
        }

        fclose(file_pointer);

    }

    // read(new_socket, buff, 4096);
    // printf("\n The buffer is %x \n", (char )buff[0] & 0xff );
    // printf("\n The length of the buffer is: %ld \n", sizeof(buff));
    printf("Recieved Cipher is: \n");
    // BIO_dump_fp (stdout, (const char *)cipher_read, rest_of_file_size);


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
    } else {
        printf("Decryption failed\n");
    }

    //write decrypted plain text to a new file
    if(local == 0){
        file_pointer = fopen(argv[1], "wb");
    }else{
        argv[1][strlen(argv[1]) - 6 ] = '\0';
        file_pointer = fopen(argv[1], "wb");
    }
    fwrite(decryptedtext, sizeof(char), rest_of_file_size, file_pointer);
    fclose(file_pointer);
    // while(1){
    //     bzero(buff, sizeof(buff));
    //     read(new_socket, buff, 4096);
    //     printf("The latest buffer data %s", buff);
        
    //     if (strncmp("EOF-COMPLETE-UFSEND-EXIT", buff, 25) == 0) {
	// 		printf("Server Exit...\n");
	// 		break;
	// 	}
    //     BIO_dump_fp (stdout, (const char *)buff, sizeof(buff));
    // }

    // printf("The buffer from ufsend is: %s", buff);


    return 0;
}
