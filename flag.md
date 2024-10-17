# FLAG
This is the 4th challenge @ `pwnable.kr`
Let's Start!

In this challenge we only get the binary.
```sh
wget http://pwnable.kr/bin/flag
file flag
# flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```
Oh shit. the file is stripped. it is gonna be super hard to reverse it.
Let's run it:
```sh
chmod +x ./flag
./flag 
# I will malloc() and strcpy the flag there.  take it.
```
OK... lets get the strings!
```sh
strings flag
```
We can see that the last string is:
```
UPX!
```
Nice! `UPX` is a binary packer allowing you to compress you binary size.
We can get the normal binary by using the following command:
```bash
sudo apt install upx # if you don't have it
upx flag -d
#                        Ultimate Packer for eXecutables
#                           Copyright (C) 1996 - 2013
# UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013
# 
#         File size         Ratio      Format      Name
#    --------------------   ------   -----------   -----------
#     887219 <-    335288   37.79%  linux/ElfAMD   flag
# 
# Unpacked 1 file.
```
Amazing! Now let's look at the file again:
```sh
file flag                                  
# flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=96ec4cc272aeb383bd9ed26c0d4ac0eb5db41b16, not stripped
```
dope.
Now let's open it using `GDB`.
```sh
# disassamble the main function
disass main
#   0x0000000000401164 <+0>:	push   %rbp
#   0x0000000000401165 <+1>:	mov    %rsp,%rbp
#   0x0000000000401168 <+4>:	sub    $0x10,%rsp
#   0x000000000040116c <+8>:	mov    $0x496658,%edi
#   0x0000000000401171 <+13>:	call   0x402080 <puts>
#   0x0000000000401176 <+18>:	mov    $0x64,%edi
#   0x000000000040117b <+23>:	call   0x4099d0 <malloc>
#   0x0000000000401180 <+28>:	mov    %rax,-0x8(%rbp)
#   0x0000000000401184 <+32>:	mov    0x2c0ee5(%rip),%rdx        # 0x6c2070 <flag>
#   0x000000000040118b <+39>:	mov    -0x8(%rbp),%rax
#   0x000000000040118f <+43>:	mov    %rdx,%rsi
#   0x0000000000401192 <+46>:	mov    %rax,%rdi
#   0x0000000000401195 <+49>:	call   0x400320
#   0x000000000040119a <+54>:	mov    $0x0,%eax
#   0x000000000040119f <+59>:	leave
#   0x00000000004011a0 <+60>:	ret
```
We got the address of flag!
Let's take a look:
```sh
x/1s *0x6c2070
# UPX...? sounds like a delivery service :)
```
Good Game.