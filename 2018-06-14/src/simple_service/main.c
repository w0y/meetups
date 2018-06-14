#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void some_vuln() {
  char buffer[4096];
  (void) fgets(buffer, 4096, stdin);
  printf(buffer);
}

int main(int argc, char **argv) {
  some_vuln();
  return EXIT_SUCCESS;
}
