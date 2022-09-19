#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include"pbkdf2_extract.h"

// write to socket
void write_data_to_socket(int socket_id, char* data ){
        write(socket_id, data, 4096 );
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}




int main(int argc, char *argv[]){

    int socket_id;

    long input_file_size_buffer = 0;

    struct sockaddr_in server_address;

    FILE *file_pointer = NULL;
    unsigned char buffer[4096];
    size_t bytes_read = 0;

    char password[100];
    int n=0;

    unsigned char* key_ret;
    unsigned char key_data[32];

    FILE *file_reader = NULL;
    char *source = NULL;
    unsigned char *source_file_data = NULL; 

    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 16;

    FILE *file_writer = NULL;
    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char *ciphertext = NULL;

    /* Buffer for the decrypted text */
   
    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len, ciphertext_len;

    socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id == -1){
        printf("Socket Creation - Status: Failed \n");
    }
    else{
        printf("Socket Creation - Status: Successfull\n");
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(8080);

    if( connect(socket_id, (struct sockaddr *)&server_address, sizeof(server_address)) != 0 ){
        printf("Connection to specified IP and port failed");
    }else{
        printf("Connection to server successfull\n ");
    }

    // write_data_to_socket(socket_id, "Hello from uf send");

   

    printf("Password:");
    while ((password[n++] = getchar()) != '\n')
        ;

    // Key that has been returned from the function
    key_ret = get_key_using_pbkdf2(password);

    file_reader = fopen("example.txt", "r");

    if(file_reader != NULL){
        if( fseek(file_reader, 0L, SEEK_END) < 0){
            printf("Error");
        }else{
            long buffer_size_read = ftell(file_reader);
            if(buffer_size_read != -1){
                source = malloc(sizeof(char) * (buffer_size_read + 1));
                printf("The size of buffer read %ld", buffer_size_read);
                input_file_size_buffer = buffer_size_read;
                printf("\n the size of source file data buffer %ld \n", sizeof(source));
                if( fseek(file_reader, 0L, SEEK_SET) < 0){
                    printf("Error");
                }
                else{
                    size_t read_len = fread(source, sizeof(char), buffer_size_read, file_reader);
                    if ( ferror( file_reader ) != 0 ) {
                        printf("Error reading file");
                    } else {
                        source[read_len++] = '\0';
                    }
                }

            }
            else{
                printf("Error reading file");
            }
        }
    }

    fclose(file_reader);

    source_file_data = (unsigned char*)source;
    free(source);

    printf("This is the data from the file %s", source_file_data);

    ciphertext = malloc( (strlen((char *)source_file_data) * sizeof(char)) + 16 );

    
    ciphertext_len = gcm_encrypt(
                        source_file_data, 
                        strlen ((char *)source_file_data),
                        key_ret,
                        iv,
                        iv_len,
                        ciphertext, 
                        tag
                    );

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    write_data_to_socket(socket_id, (char *)ciphertext);

    file_writer = fopen("example.txt.ufsec", "wb");
    fwrite(iv, sizeof(char), 16, file_writer);
    fwrite(ciphertext, sizeof(char), 1151, file_writer);
    fwrite(tag, sizeof(char), 16, file_writer);
    fclose(file_writer);

    


     printf("\nThe from decipher ciphered text is: %s \n", ciphertext);

    //  printf("\nThe from decipher ciphered text length is: %s \n", ciphertext_len);

    printf("\n\n This is the total text that will be written: \n %s \n\n", iv);

    
    printf("The size after decryption: %ld", input_file_size_buffer);
    printf("\nThe ciphered text is: %s \n", ciphertext);

    write_data_to_socket(socket_id, (char *)ciphertext);

   

   

    file_pointer = fopen("example.txt.ufsec", "rb");

    if(file_pointer != NULL){
        while((bytes_read = fread(buffer, 1, sizeof(buffer), file_pointer))){
             printf("\nthe buffer read is : %s \n", buffer);
             BIO_dump_fp (stdout, (const char *)buffer,1151);
             write_data_to_socket(socket_id, (char *)buffer);
        }
    }

    fclose(file_pointer);

    write_data_to_socket(socket_id, "EOF-COMPLETE-UFSEND-EXIT");

    return 0;
}

