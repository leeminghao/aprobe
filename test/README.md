# Test

## build

```
armv7a-linux-androideabi16-clang test.c -shared -o libhello.so
armv7a-linux-androideabi16-clang main.c -L . -I . -lhello
```

## run

```
adb push a.out libhello.so /data/local/tmp/
adb shell "export LD_LIBRARY_PATH=/data/local/tmp; /data/local/tmp/a.out"
hello
```

## trace

### readelf -s

```
arm-linux-androideabi-readelf -s ./libhello.so

Symbol table '.dynsym' contains 10 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND __cxa_atexit@LIBC (2)
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND __cxa_finalize@LIBC (2)
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND malloc@LIBC (2)
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@LIBC (2)
     5: 00000000     0 FUNC    GLOBAL DEFAULT  UND snprintf@LIBC (2)
     6: 00002004     0 NOTYPE  GLOBAL DEFAULT  ABS _edata
     7: 00002004     0 NOTYPE  GLOBAL DEFAULT  ABS _end
     8: 00002004     0 NOTYPE  GLOBAL DEFAULT  ABS __bss_start
     9: 00000478   120 FUNC    GLOBAL DEFAULT   12 hello_world
```

### objdump -D

```
arm-linux-androideabi-objdump -D ./libhello.so

...

00000478 <hello_world>:
 478:	e92d4800 	push	{fp, lr}
 47c:	e1a0b00d 	mov	fp, sp
 480:	e24dd010 	sub	sp, sp, #16
 484:	e3000400 	movw	r0, #1024	; 0x400
 488:	ebffffe0 	bl	410 <malloc@plt>
 48c:	e50b0004 	str	r0, [fp, #-4]
 490:	e51b0004 	ldr	r0, [fp, #-4]
 494:	e300e000 	movw	lr, #0
 498:	e15e0000 	cmp	lr, r0
 49c:	0a00000e 	beq	4dc <hello_world+0x64>
 4a0:	e59f0040 	ldr	r0, [pc, #64]	; 4e8 <hello_world+0x70>
 4a4:	e08f2000 	add	r2, pc, r0
 4a8:	e59f003c 	ldr	r0, [pc, #60]	; 4ec <hello_world+0x74>
 4ac:	e08f3000 	add	r3, pc, r0
 4b0:	e51b0004 	ldr	r0, [fp, #-4]
 4b4:	e3001400 	movw	r1, #1024	; 0x400
 4b8:	ebffffd7 	bl	41c <snprintf@plt>
 4bc:	e59f1020 	ldr	r1, [pc, #32]	; 4e4 <hello_world+0x6c>
 4c0:	e08f1001 	add	r1, pc, r1
 4c4:	e51b2004 	ldr	r2, [fp, #-4]
 4c8:	e58d0008 	str	r0, [sp, #8]
 4cc:	e1a00001 	mov	r0, r1
 4d0:	e1a01002 	mov	r1, r2
 4d4:	ebffffd3 	bl	428 <printf@plt>
 4d8:	e58d0004 	str	r0, [sp, #4]
 4dc:	e1a0d00b 	mov	sp, fp
 4e0:	e8bd8800 	pop	{fp, pc}
 4e4:	00000030 	andeq	r0, r0, r0, lsr r0
 4e8:	0000004c 	andeq	r0, r0, ip, asr #32
 4ec:	00000047 	andeq	r0, r0, r7, asr #32
```

对 malloc 函数的调用对应于指令:

```
 488:	ebffffe0 	bl	410 <malloc@plt>
```

跳转到了地址 410。看看这个地址里有什么吧：

```
00000410 <malloc@plt>:
 410:	e28fc600 	add	ip, pc, #0, 12 ; @由于ARM三级流水，PC = 410 + 8
 414:	e28cca01 	add	ip, ip, #4096	; 0x1000
 418:	e5bcfbdc 	ldr	pc, [ip, #3036]!	; 0xbdc
```

跳转到了 .plt 中，经过了几次地址计算，最后跳转到了地址 1ff4 中的值指向的地址处，1ff4 是个函数指针。

稍微解释一下：因为 arm 处理器使用 3 级流水线，所以第一条指令取到的 pc 的值是当前执行的指令地址 + 8。 于是：410 + 8 + 1000 + bdc = 1ff4。

地址 1ff4 在哪里呢：

```
00001fe0 <_GLOBAL_OFFSET_TABLE_>:
	...
    1fec:	000003e4 	andeq	r0, r0, r4, ror #7
    1ff0:	000003e4 	andeq	r0, r0, r4, ror #7
    1ff4:	000003e4 	andeq	r0, r0, r4, ror #7
    1ff8:	000003e4 	andeq	r0, r0, r4, ror #7
    1ffc:	000003e4 	andeq	r0, r0, r4, ror #7
```

果然，在 .got 里。

顺便再看一下 .rel.plt：

```
arm-linux-androideabi-readelf -r libhello.so

Relocation section '.rel.plt' at offset 0x3bc contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
00001fec  00000216 R_ARM_JUMP_SLOT   00000000   __cxa_finalize@LIBC
00001ff0  00000116 R_ARM_JUMP_SLOT   00000000   __cxa_atexit@LIBC
00001ff4  00000316 R_ARM_JUMP_SLOT   00000000   malloc@LIBC
00001ff8  00000516 R_ARM_JUMP_SLOT   00000000   snprintf@LIBC
00001ffc  00000416 R_ARM_JUMP_SLOT   00000000   printf@LIBC
```

malloc 的地址居然正好存放在 1ff4 里。我们的 main.c 应该改成这样：

```
#include <test.h>

#include <stdio.h>
#include <stdlib.h>

void *h_malloc(size_t size)
{
  printf("%zu bytes memory are allocated\n", size);
  return malloc(size);
}

int main(int argc, char *argv[])
{
  void **p = (void **)0x1ff4;
  *p = (void *)h_malloc; // do hook

  hello_world();
}
```

编译运行一下：

```
armv7a-linux-androideabi16-clang main_static_hook.c -L . -I . -lhello -o a.static-hook.out
adb push a.static-hook.out /data/local/tmp
adb shell "export LD_LIBRARY_PATH=/data/local/tmp; /data/local/tmp/a.static-hook.out"
Segmentation fault
```

思路是正确的。但之所以还是失败了，是因为这段代码存在下面的 3 个问题：

1ff4 是个相对内存地址，需要把它换算成绝对地址。
1ff4 对应的绝对地址很可能没有写入权限，直接对这个地址赋值会引起段错误。
新的函数地址即使赋值成功了，my_malloc 也不会被执行，因为处理器有指令缓存（instruction cache）。
我们需要解决这些问题。

```
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
```