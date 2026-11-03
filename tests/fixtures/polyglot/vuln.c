#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void greet(const char *name) {
  char buf[64];
  strcpy(buf, name);
  system(buf);
}
int main(int argc, char **argv) {
  if (argc > 1) greet(argv[1]);
  return 0;
}
