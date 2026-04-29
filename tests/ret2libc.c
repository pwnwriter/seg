// Ret2libc target — NX enabled, no canary, partial RELRO
// Compile: gcc -fno-stack-protector -no-pie -o ret2libc ret2libc.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vuln() {
    char buf[128];
    puts("Tell me something:");
    read(0, buf, 512);
}

int main() {
    puts("Welcome to the ret2libc challenge!");
    vuln();
    puts("Bye!");
    return 0;
}
