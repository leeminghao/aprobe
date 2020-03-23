#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <test.h>

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr) + PAGE_SIZE)

void *h_malloc(size_t size)
{
  printf("%zu bytes memory are allocated by libhello.so\n", size);
  return malloc(size);
}

void hook()
{
  char       line[512];
  FILE      *fp;
  uintptr_t  base_addr = 0;
  uintptr_t  addr;

  //find base address of libhello.so
  // /proc/maps 返回的是指定进程的内存空间中 mmap 的映射信息，包括各种动态库、
  // 可执行文件（如：linker），栈空间，堆空间，甚至还包括字体文件。
  // 我们的 libhello.so 在 maps 中有 3 行记录。offset 为 0 的第一行的起始地址
  // b6ec6000 在绝大多数情况下就是我们寻找的基地址。
  if (NULL == (fp = fopen("/proc/self/maps", "r"))) return;
  while (fgets(line, sizeof(line), fp)) {
    if(NULL != strstr(line, "libhello.so") &&
       sscanf(line, "%"PRIxPTR"-%*lx %*4s 00000000", &base_addr) == 1)
      break;
  }
  fclose(fp);
  if(0 == base_addr) return;

  //the absolute address
  addr = base_addr + 0x1ff4;

  // add write permission
  // maps返回的信息中已经包含了权限访问信息。如果要执行 hook，就需要写入的权限，可以使用 mprotect 来完成：
  mprotect((void *)PAGE_START(addr), PAGE_SIZE, PROT_READ | PROT_WRITE);

  //replace the function address
  *(void **)addr = h_malloc;

  //clear instruction cache
  __builtin___clear_cache((void *)PAGE_START(addr), (void *)PAGE_END(addr));
}

int main()
{
  hook();

  hello_world();
  return 0;
}
