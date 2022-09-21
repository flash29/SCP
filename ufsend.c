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
#include <openssl/rand.h>
#include"pbkdf2_extract.h"

// write to socket
void write_data_to_socket(int socket_id, char* data, size_t length ){
        write(socket_id, data, length );
}

/*
For handling any error that are arised during encryption
*/

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
/*
This function carries out the AES 256 Encryption
*/
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

    char *ip_address, *port_input;
    char *look = ":";
    int port_no;
    int local = 0;
    /*
    if local is 0 then that means -d is selected (Send to a port number on the specified ip addr)
    if local is 1 then -l is the given input. (Run Locally)
    */

    if(argc < 3){
        printf("Insuffiecient number of outputs");
        return 0;
    }

    local = strcmp(argv[2], "-d");

    /* if we are using -d(dumps) mode then we are splitting the input 
    into two parts and getting the IP Address and PORT number 
    */
    if(argc == 4 && local == 0 ){
        ip_address = strtok(argv[3], look);
        port_input = strtok(NULL, look);

        // printf("This is the ip %s and the port %s", ip_address, port_input);
        port_no = atoi(port_input);
    }

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
    unsigned char *random_iv = malloc(iv_len);

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
    /*
    If we are in dumps(-d) mode, then we have to connect to the IP address and port number
    So that connection setup is carried out here 
    */
    if (local == 0){

        socket_id = socket(AF_INET, SOCK_STREAM, 0);
        if(socket_id == -1){
            printf("Socket Creation - Status: Failed \n");
        }
        else{
            // printf("Socket Creation - Status: Successfull\n");
        }

        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = inet_addr(ip_address);
        server_address.sin_port = htons(port_no);

        if( connect(socket_id, (struct sockaddr *)&server_address, sizeof(server_address)) != 0 ){
            printf("Connection to specified IP and port failed");
        }else{
            printf("Connection to server successfull\n ");
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
    Read the input file and store the entire file data on to the buffer(source variable)
    */

    file_reader = fopen(argv[1], "rb");

    if(file_reader != NULL){
        if( fseek(file_reader, 0L, SEEK_END) < 0){
            printf("Error");
        }else{
            long buffer_size_read = ftell(file_reader);
            if(buffer_size_read != -1){
                source = malloc(sizeof(char) * (buffer_size_read + 1));
                input_file_size_buffer = buffer_size_read;
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

    /*
    Generate cryptographically psuedorandom number for IV 
    */

    RAND_bytes( random_iv, (int)iv_len);

    printf("This is the source file data is: %s \n", source_file_data);
    BIO_dump_fp (stdout, (char *)source_file_data, input_file_size_buffer);
    printf("\nThis is the size from the buffer %ld \n", input_file_size_buffer);
    printf("This is the length from strlen %lu \n", strlen( (char *)source_file_data ));
    printf("This is the iv string : %s", random_iv);
    BIO_dump_fp (stdout, (const char *)random_iv, iv_len);

    /*
    Allocate memory to ciphertext and carry out the encryption of the data from the 
    input file.
    */

    ciphertext = malloc( input_file_size_buffer );
   
    
    ciphertext_len = gcm_encrypt(
                        source_file_data, 
                        input_file_size_buffer ,
                        key_ret,
                        random_iv,
                        iv_len,
                        ciphertext, 
                        tag
                    );

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    printf("This is the tag %s \n", tag);
    BIO_dump_fp (stdout, (const char *)tag, 16);
     

    /*
    if we are in -d mode then send the IV, size of the encrypted text 
    and the encrypted text and the tag to the connected socket. 
    */
    if(local == 0){
        printf("Transmitting to %s:%s \n", ip_address, port_input);
        char *temp_size = malloc(8);
        sprintf(temp_size, "%ld", input_file_size_buffer);
        write_data_to_socket(socket_id, (char *)random_iv, iv_len);
        write_data_to_socket(socket_id, temp_size , 8);
        write_data_to_socket(socket_id, (char *)ciphertext, input_file_size_buffer);
        write_data_to_socket(socket_id, (char *)tag, 16);
    }
    
    /*
    Write the IV-ciphertext-tag data to the input filename with an extension of 
    ".ufsec".
    */

   if( access(strcat(argv[1], ".ufsec"), F_OK) == 0 ){
    printf("\n Output file already exists try again with a different name or deleting the file \n");
    return 33;
   }


    file_writer = fopen(argv[1], "wb");
    fwrite(random_iv, sizeof(char), 16, file_writer);
    fwrite(ciphertext, sizeof(char), input_file_size_buffer, file_writer);
    fwrite(tag, sizeof(char), 16, file_writer);
    fclose(file_writer);

    
    if(local == 0){
         write_data_to_socket(socket_id, "EOF-COMPLETE-UFSEND-EXIT", 24);
    }
    printf("Successfully Encrypted data and sent %ld bytes", input_file_size_buffer);

    return 0;
}

