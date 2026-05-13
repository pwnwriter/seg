// Classic buffer overflow — no canary, no PIE
// Compile: gcc -fno-stack-protector -no-pie -o bof_basic bof_basic.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gets() removed from modern glibc headers; declare it manually for this intentionally-vulnerable binary
extern char *gets(char *s);

void win() {
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    printf("Enter input: ");
    gets(buf);
    printf("You said: %s\n", buf);
}

int main() {
    vuln();
    return 0;
}
