# FD
This is the 1st challenge @ `pwnable.kr`
Let's Start!

## Source Code
Let's take a look at the source code of the program:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```
The main function contains all the logic of the program:
- Takes a command line argument
- subtracts 4660 (or `0x1234`)
- using it as an `FD`
- reading 32 bytes out of it.
- compares the string to "LETMEWIN\n"

## About `File Descriptors` in Linux
`Chat-GPT` says:
*A file descriptor is a low-level integer handle used to identify an open file or other input/output resources, such as sockets or pipes.*
There are 3 pre-defined `FDs` that you can use:
- 0: Standard Input (`stdin`)
- 1: Standard Output (`stdout`)
- 2: Standard Error (`stderr`)
For example, you can read from `stdin` using this C code:
```c
char buf[32];
read(0, buf, 32);
```

## Exploit!
So, now you might think *But, how can I know the right FD?*.
Well, what if we make the program read from `STDIN`, we should be able to control input!
```
fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```
And that is it! we have successfully exploited the program!