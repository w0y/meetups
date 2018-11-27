// Compile with: gcc -no-pie -O0 ex1.c -o ex1
#include <stdio.h>
#include <stdlib.h>

void target_func(const char *input) {
    printf("%s\n", input);
}

int main(int argc, char **argv) {
    target_func("EXAMPLE1_STRING");
    
    return EXIT_SUCCESS;
}