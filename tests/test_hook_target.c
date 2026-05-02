/* test binary for seg hook */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("before puts\n");
    puts("hello from hook target");
    printf("rand() = %d\n", rand());
    return 0;
}
