# buffer overflow 0

**CTF**: picoCTF 2022
**Category:** Binary Exploitation
**Difficulty**: Medium
**Tags**: `gets`, `buffer-overflow`

**Writeup by:** Linus Kundur-Zourntos
#### Challenge Description
In this challenge, you are given a binary, along with its source code that can be exploited in some way with a buffer overflow to obtain a flag. 
#### Environment Setup
Tools: `file`, `gdb`, `checksec`, `pwntools`
OS: Ubuntu 22.04.5 LTS x86_64
#### Initial Analysis
Using `file` and `checksec` we can get some basic information from the executable

`file` output:
```
vuln: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b53f59f147e1b0b087a736016a44d1db6dee530c, for GNU/Linux 3.2.0, not stripped
```
└ Most important thing we learn is that this a 32-bit executable, which will come in handy for  later analysis

`checksec` output: 
```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
└ We learn the program has no stack canary, which will make any potential buffer overflow vulnerabilities much easier to exploit.
#### Vulnerability
Two security issues are discovered through inspection of the program's source code.

Here is the entire program source for reference:
```c
  1 #include <stdio.h>
  2 #include <stdlib.h>
  3 #include <string.h>
  4 #include <signal.h>
  5 
  6 #define FLAGSIZE_MAX 64
  7 
  8 char flag[FLAGSIZE_MAX];
  9 
 10 void sigsegv_handler(int sig) {
 11   printf("%s\n", flag);
 12   fflush(stdout);
 13   exit(1);
 14 }
 15 
 16 void vuln(char *input){
 17   char buf2[16];
 18   strcpy(buf2, input);
 19 }
 20 
 21 int main(int argc, char **argv){
 22 
 23   FILE *f = fopen("flag.txt","r");
 24   if (f == NULL) {
 25     printf("%s %s", "Please create 'flag.txt' in this directory with your",
 26                     "own debugging flag.\n");
 27     exit(0);
 28   }
 29 
 30   fgets(flag,FLAGSIZE_MAX,f);
 31   signal(SIGSEGV, sigsegv_handler); // Set up signal handler
 32 
 33   gid_t gid = getegid();
 34   setresgid(gid, gid, gid);
 35 
 36 
 37   printf("Input: ");
 38   fflush(stdout);
 39   char buf1[100];
 40   gets(buf1);
 41   vuln(buf1);
 42   printf("The program will exit now\n");
 43   return 0;
 44 }                    
```

The first security flaw can be identified on line 40 with the use of the `gets()` function as a means of reading input into a buffer. `gets()` is a notoriously problematic, as it will continuously read data into an input buffer until it encounters a newline, regardless of the size of the buffer. This is in contrast to more secure functions such as `fgets()` that *require* you to specify an input buffer length or `scanf()` which provide an option to specify an input field width.

The second security flaw is identified through the use of `strcpy()` within the `vuln()` function on line 18. `strcpy()` will continue to copy characters from the source string to e destination string until it encounters a null terminator `\0`. Issues arise when the destination string is smaller in size than the source string. In this case, it is possible that `strcpy()` attempts to copy more bytes to the destination than its size can handle, creating a buffer overflow.

In the case of this program `buf1` (the source) is 100 bytes in size, meanwhile `buf2` is only 16 bytes in size. Even if the user's input is within the allocated size of `buf1`, there is still a chance that `buf2` will be overflowed as the null byte `\0` in `buf1` may be well past the size constraint of `buf2`. 
#### Exploit Strategy
In order to get the flag for this challenge, you must cause the program to crash in some way. Given that the two security flaws identified enable buffer overflows, it makes most sense to try and crash the program using one of these. 

The objective is to overwrite a critical piece of memory, such as a memory address on the stack, that once corrupted will cause the program to attempt to read from or write to memory it does not have permission to access. When this happens, the kernel delivers SIGSEGV to the process, terminating it and giving us the flag. 

In the initial analysis it is found that the executable was not compiled with stack canary enabled. This means that we can easily overflow both `buf1` and `buf2` with as many bytes as we want.

The strategy is simply to write a huge number of bytes into `buf1` hoping that we overwrite something important after the initial `gets()` call or after it is copied into `buf2`. 
#### Exploit Code
I've found that writing 20 `A` characters  as input is enough to overwrite something important. Specifically, it is the address to the string `"the program will exit now"` used by `printf()` on line 42 of the source. 

The following exploit is developed using `pwntools`
```python
import pwn

r = pwn.remote("XXXXX", XXXXX) # enter the specific credentials for your instance.
s = r.recvuntil('Input:')

r.sendline(b"A" * 20);
r.interactive()
```
#### Flag/Output
The program output is simply the flag which is:
```
 picoCTF{ov3rfl0ws_ar3nt_that_bad_ef01832d}
```
#### Takeaways
This program given in this challenge is one that allows the user to write as much data as it wants to an input buffer `buf1` and by the call to `strcpy()` another buffer `buf2`. 

Unlike other buffer overflow challenges that require you to redirect code execution through overwriting return addresses or have very basic defenses set in place, this one only requires that you crash the program, greatly simplifying the exploit strategy.
#### Defense Discussion
The simplest way to make the program more secure would be to use a modern compiler. In the case that a programmer uses `gets()` the compiler warns the programmer:
```
vuln.c:(.text+0x184): warning: the `gets' function is dangerous and should not be used.

```
Assuming the programmer recognizes their mistake, this would solve the first security flaw. 

To address the second security flaw, the programmer could use `strncpy()` opposed to `strcpy()`. `strncpy()` forces the programmer to specify the number of bytes to write to the buffer.

Another positive side-effect of using a modern compiler is that, unless specific options are passed, all modern memory-corruption defenses will be enabled. 

Here is the output of checksec with the recompiled executable: 
```
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
