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

int main(int argc, char *argv[]){

    struct sockaddr_in server_address;
    int server_address_size = sizeof(server_address);
    int socket_id, new_socket;
    char buff[4096];

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

    read(new_socket, buff, 4096);
    printf("\n The buffer is %x \n", (char )buff[0] & 0xff );
    printf("\n The length of the buffer is: %ld \n", sizeof(buff));
    BIO_dump_fp (stdout, (const char *)buff, 1151);

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

    printf("The buffer from ufsend is: %s", buff);


    return 0;
}
