#include <stdio.h>
#include <stdint.h>
#include "print.h"

void puthbuf(uint8_t *buf, int len)
{
    int i;
    for(i=0; i<len; i++){
        printf("%02X ", buf[i]);
    }
}

void putlen(int len)
{
    char buf[10];
    sprintf(buf, "<%d> ", len);
    printf("%6s", buf);
}

void print_spliter(void)
{
    printf("\n\n--------------------------------------------------------------------------------\n");
}
