#include <stdio.h>
#include <stdlib.h>
#include"printing.h"


int main(int argc, char *argv[]) {


    printf("Hello from program 1 \n");

    for(int i=1; i< argc; i++){
        printf("This is the %d argument with value %s\n", i, argv[i]);
    }
    hello_print();

    return 0;
}