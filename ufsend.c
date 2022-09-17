#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include"pbkdf2_extract.h"

// write to socket
void write_data_to_socket(int socket_id, char* data ){
        write(socket_id, data, 4096 );
}

int main(int argc, char *argv[]){

    // int socket_id;

    // struct sockaddr_in server_address;

    // FILE *file_pointer = NULL;
    // unsigned char buffer[4096];
    // size_t bytes_read = 0;

    char password[100];
    int n=0;

    unsigned char* key_ret;
    unsigned char key_data[32];

    // socket_id = socket(AF_INET, SOCK_STREAM, 0);
    // if(socket_id == -1){
    //     printf("Socket Creation - Status: Failed \n");
    // }
    // else{
    //     printf("Socket Creation - Status: Successfull\n");
    // }

    // server_address.sin_family = AF_INET;
    // server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    // server_address.sin_port = htons(8080);

    // if( connect(socket_id, (struct sockaddr *)&server_address, sizeof(server_address)) != 0 ){
    //     printf("Connection to specified IP and port failed");
    // }else{
    //     printf("Connection to server successfull\n ");
    // }

    // write_data_to_socket(socket_id, "Hello from uf send");

    // file_pointer = fopen("example.txt", "r");

    // if(file_pointer != NULL){
    //     while((bytes_read = fread(buffer, 1, sizeof(buffer), file_pointer))){
    //          write_data_to_socket(socket_id, (char *)buffer);
    //     }
    // }

    printf("Password:");
    while ((password[n++] = getchar()) != '\n')
        ;

    key_ret = get_key_using_pbkdf2(password, key_ret);
    


    printf("Got this key: ");
    for (size_t i=0; i<32; ++i)
        printf("%02x ", key_ret[i]);
    printf("\n");

    // write_data_to_socket(socket_id, "EOF-COMPLETE-UFSEND-EXIT");

    return 0;
}

