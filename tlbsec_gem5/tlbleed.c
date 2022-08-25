#include "tlbleed.h"

#define buf_size 4096*16*4*2
#define uint64_t unsigned long long int

char* allocate_buffer()
{
    /* allocate buffer that is a particular page number offset from the base, is RWX and contains usable instructions
     * in case we want to execute it. it all points to the same physical page so we don't have to worry about the effects
     * of the cache too much when calculating latency, but ought to be just seeing the TLB latency.
     */
	/*assert(p >= 0);
	volatile char *target = (void *) (VTARGET+p*PAGE);
	volatile char *ret;
	ret = mmap((void *) target, PAGE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_FILE|MAP_FIXED, fd, 0);
	if(ret == MAP_FAILED) {
		perror("mmap");
           exit(1);
	}
	if(ret != (volatile char *) target) { fprintf(stderr, "Wrong mapping\n"); exit(1); }
    *ret;
	memset((char *) ret, 0xc3, PAGE); // RETQ instruction */

    char* buffer = (char*) malloc(buf_size);

    for(int i=0; i<buf_size; i+=4096){
        buffer[i] = 1;
    }
    return buffer;
}

int main(char* argv[], int argc){
    void* buffer = allocate_buffer();

    uint64_t a, b;
    printf("Buffer: %p\n",buffer);
    printf("Buffer+128: %p\n", buffer+128);

    // TLB Miss , Cache Miss
    a = rdtsc();
    maccess(buffer);
    b = rdtsc();

    printf("Time was %llu \n", b-a);

    //flush(buffer);

    // TLB Hit , Cache Miss
    a = rdtsc();
    maccess(buffer+128);
    b = rdtsc();

    printf("Time was %llu \n", b-a);

    longnop();

    maccess(buffer+4096*16);
    maccess(buffer+4096*16*2);
    maccess(buffer+4096*16*3);
    maccess(buffer+4096*16*4);

    longnop();

    a = rdtsc();
    maccess(buffer);
    b = rdtsc();
    printf("Time was %llu \n", b-a);

    

    

    

}