#include <stdio.h>
#include <unistd.h>
#include "libforksrv.h"

char buff[10] = {0};

void fuzzme(char* data) {
    if (data[0]  == 'f') {
    if (data[1]  == 'u') {
    if (data[2]  == 'z') {
    if (data[3]  == 'z') {
    if (data[4]  == 'm') {
    if (data[5]  == 'e') {
        *(int*)0xcafecafe = 0x41414141;
    }}}}}}
    return;
}

int main() {
    printf("Start target main\n");

    __cs_start_forkserver();
    
    printf("\n");
    if (read(STDIN_FILENO, buff, 10) < 0)
    {
    fprintf(stderr, "Couldn't read stdin.\n");
    }
    fuzzme(buff);
    return 0;
}