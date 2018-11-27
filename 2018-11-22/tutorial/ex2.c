// Compile with: gcc -no-pie -O0 ex2.c -o ex2
#include <stdio.h>
#include <stdlib.h>

const char *SECRET = "THE_SECRET_WAS_HERE";

void print_scrambled(const unsigned char *scrambled) {
    puts("Scrambled secret is:");
    for (int i = 0; i < 19; i++)
        printf("%02x", scrambled[i]);
    puts("");
}

void crack_me(const char *flag) {
    unsigned char scramble_buffer[19];

    // Welcome message, so we can find the function per string
    puts("Welcome!");

    // Just shuffle the characters randomly
    scramble_buffer[ 0] = SECRET[10];
    scramble_buffer[ 1] = SECRET[ 4];
    scramble_buffer[ 2] = SECRET[15];
    scramble_buffer[ 3] = SECRET[14];
    scramble_buffer[ 4] = SECRET[12];
    scramble_buffer[ 5] = SECRET[ 1];
    scramble_buffer[ 6] = SECRET[18];
    scramble_buffer[ 7] = SECRET[ 6];
    scramble_buffer[ 8] = SECRET[ 7];
    scramble_buffer[ 9] = SECRET[11];
    scramble_buffer[10] = SECRET[ 3];
    scramble_buffer[11] = SECRET[16];
    scramble_buffer[12] = SECRET[ 8];
    scramble_buffer[13] = SECRET[ 5];
    scramble_buffer[14] = SECRET[ 0];
    scramble_buffer[15] = SECRET[13];
    scramble_buffer[16] = SECRET[17];
    scramble_buffer[17] = SECRET[ 2];
    scramble_buffer[18] = SECRET[ 9];

    // XOR each character with the last one
    for (int i = 1; i < 19; i++)
        scramble_buffer[i] ^= scramble_buffer[i - 1];

    // Print the scrambled result
    print_scrambled(scramble_buffer);
}

int main(int argc, char **argv) { 
    crack_me(SECRET);
    return EXIT_SUCCESS;
}