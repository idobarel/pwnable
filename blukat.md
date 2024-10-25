# BLUKAT
To solve this one you just need to run:
```bash
id
# uid=1104(blukat) gid=1104(blukat) groups=1104(blukat),1105(blukat_pwn)
ls -l
# total 20
# -r-xr-sr-x 1 root blukat_pwn 9144 Aug  8  2018 blukat
# -rw-r--r-- 1 root root        645 Aug  8  2018 blukat.c
# -rw-r----- 1 root blukat_pwn   33 Jan  6  2017 password
```
As you can see we are part of the `blukat_pwn` group which have `read` permissions on the password file!
We can use `cat` to print it:
```bash
cat password
# cat: password: Permission denied
```
HUH? let's use `xxd`:
```bash
xxd password
# 00000000: 6361 743a 2070 6173 7377 6f72 643a 2050  cat: password: P
# 00000010: 6572 6d69 7373 696f 6e20 6465 6e69 6564  ermission denied
# 00000020: 0a 
```
As you can see the content of the file is: `cat: password: Permission denied`. We can paste it as a password:
```bash
echo 'cat: password: Permission denied' | ./blukat
```
And we have the flag!
```
Pl3as_DonT_Miss_youR_GrouP_Perm!!
```