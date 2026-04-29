// Use-after-free / heap challenge
// Compile: gcc -no-pie -o heap_uaf heap_uaf.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct note {
    void (*print)(struct note *);
    char content[64];
};

void print_note(struct note *n) {
    printf("Note: %s\n", n->content);
}

void shell() {
    system("/bin/sh");
}

int main() {
    struct note *a = malloc(sizeof(struct note));
    a->print = print_note;
    strcpy(a->content, "hello world");

    printf("Note created at %p\n", (void *)a);
    a->print(a);

    free(a);

    // UAF: allocate same size, overwrite function pointer
    struct note *b = malloc(sizeof(struct note));
    printf("New alloc at %p\n", (void *)b);
    read(0, b, sizeof(struct note));

    // Trigger UAF
    a->print(a);

    return 0;
}
