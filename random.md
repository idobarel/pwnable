# RANDOM
This is the 6th challenge @ `pwnable.kr`
Let's Start!

We have the source code:
```c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!

	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}
```
Looks like the usage of `rand` is wrong (no seed).
The key is a static key.
I've created a program to dump the key:
```C
int main(){
	unsigned int random = rand();
	printf("%d\n", random);
	return 0;
}
```
Compile and run:
```bash
gcc -o key key.c
./key
# 1804289383
```
use python to XOR this number with `0xdeadbeef`:
```python
1804289383 ^ 0xdeadbeef
# 3039230856
```
and:
```bash
./random
3039230856
# Good!
# Mommy, I thought libc random is unpredictable...
```
Good Day!