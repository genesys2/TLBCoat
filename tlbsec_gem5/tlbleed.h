#include <sys/mman.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define VTARGET 0x300000000000ULL
#define PAGE 4096

uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

void flush(void* p) {
    asm volatile ("clflush 0(%0)\n"
      :
      : "c" (p)
      : "rax");
}

void maccess(void* p)
{
  asm volatile ("movq (%0), %%rax\n"
    :
    : "c" (p)
    : "rax");
}

void longnop()
{
  asm volatile ("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n");
}

static int createfile(const char *fn)
{
        int fd;
#ifndef NO_PTHREAD
        struct stat sb;
        char sharebuf[PAGE];
        if(stat(fn, &sb) != 0 || sb.st_size != PAGE) {
                fd = open(fn, O_RDWR | O_CREAT | O_TRUNC, 0644);
                if(fd < 0) {
			perror("open");
                        fprintf(stderr, "createfile: couldn't create shared file %s\n", fn);
                        exit(1);
                }
                if(write(fd, sharebuf, PAGE) != PAGE) {
                        fprintf(stderr, "createfile: couldn't write shared file\n");
                        exit(1);
                }
                return fd;
        }

        assert(sb.st_size == PAGE);
#endif

        fd = open(fn, O_RDWR, 0644);
        if(fd < 0) {
            perror(fn);
                fprintf(stderr, "createfile: couldn't open shared file\n");
                exit(1);
        }
        return fd;

}