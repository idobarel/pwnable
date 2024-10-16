# Collision
This is the 2nd challenge @ `pwnable.kr`
Let's Start!

## Source Code
Let's take a look at the source code of the program:
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```
The flow of the program:
- take a 20 byte long input from the commandline
- using `check_password`
	- casting the input string (`char*`) to `int*`.
	- summing up the results and returning the value
- comparing the results to `hashcode` (`0x21DD09EC`)

## About `Casting` in C
Casting is the operation of converting a variable from one type to another.
You can use casting like this:
```C
const char* p;
int* ip = (int*)p;
```
the variable `ip` will contain the memory of `p`, but will be represented as an array (pointer) of integers instead of array (pointer) of chars.

## Exploit!
Ok, Let's exploit this program!
The input length must be 20 bytes. because every int is 4 bytes long, we will have 5 numbers in total.
The way that the program is calculating the hash in the `check_password` function is by summing up the numbers in the array.
Therefore, We need to create a buffer which contains 5 numbers which sums up to 568134124 (`0x21DD09EC`).
Calculation:
```
113626825 * 4 + 113626824 * 1 = 568134124
113626825 = \x06\xC6\x6D\x09
113626824 = \x06\xC6\x6D\x08
payload = '\x06\xC6\x6D\x09\x06\xC6\x6D\x09\x06\xC6\x6D\x09\x06\xC6\x6D\x09\x06\xC6\x6D\x08'
```
run the exploit:
```sh
./col `echo -en '\x06\xC6\x6D\x09\x06\xC6\x6D\x09\x06\xC6\x6D\x09\x06\xC6\x6D\x09\x06\xC6\x6D\x08'`
# passcode length should be 20 bytes
```
What? well after I didnt understand for a while it turns out that my payload containing a non-printable characters, therefore the program wont be able to read those bytes.
After trying some options I found out that:
```
0x06C5CEC8 * 4 + 0x06C5CECC = 0x21DD09EC
113491776 * 4 + 113491164 = 567458268
payload = '\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06'
```
And exploiting it:
```sh
./col `echo -en '\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06'`
# daddy! I just managed to create a hash collision :)
```
And that is it!