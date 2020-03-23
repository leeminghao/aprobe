#include <test.h>

#include <stdio.h>
#include <stdlib.h>

void *h_malloc(size_t size)
{
  printf("%zu bytes memory are allocated by libhello.so\n", size);
  return malloc(size);
}

int main(int argc, char *argv[])
{
  void **p = (void **)0x1ff4;
  *p = (void *)h_malloc; // do hook

  hello_world();
}
