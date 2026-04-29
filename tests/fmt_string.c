// Format string vulnerability — partial RELRO, no PIE
// Compile: gcc -no-pie -o fmt_string fmt_string.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char secret[] = "flag{y0u_f0und_m3}";

void backdoor() {
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
}

int main() {
    char buf[256];
    printf("What is your name? ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    printf("\nGoodbye!\n");
    return 0;
}
