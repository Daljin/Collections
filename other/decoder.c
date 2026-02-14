#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main (int argc, char **argv) 
{
  //Place your encoded shellcode here. use the xor_encoder.c
	char buf[] = "";
	
	char xor_key = 'J';
	int arraysize = (int) sizeof(buf);
	
	for (int i=0; i<arraysize; i++)
	{
		buf[i] = buf[i]^xor_key;
	}
	
	int (*ret)() = (int(*)())buf;
	ret();
	
	return 0;
}
