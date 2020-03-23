#include <stdlib.h>
#include <stdio.h>

void hello_world()
{
  char *buf = malloc(1024);
  if(NULL != buf)
  {
    snprintf(buf, 1024, "%s", "hello\n");
    printf("%s", buf);
  }
}
