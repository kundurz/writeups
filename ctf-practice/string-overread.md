# string overread

**CTF**: pwn-style challenge
**Category**: Binary Exploitation
**Tags:** `buffer-overflow`, `string-overread`, `information-disclosure`

**Writeup by:** Linus Kundur-Zourntos

*Certain implementation details are intentionally abstracted to respect platform usage policies*
#### Challenge Description
You must overflow a buffer and leak the flag. 

The program prompts you to enter a payload size, after which, you enter your payload and it prints back the string you said: 
```
Payload size: 12
Send your payload (up to 12 bytes)!
MY_PAYLOAD
You said: MY_PAYLOAD
```

#### Environment Setup
Tools: `file`, `gdb,` `checksec`
OS: Ubuntu 22.04.5 LTS x86_64
#### Initial analysis
`file` and `checksec` are used together to gather information on the executable.

`file` output:  
```
challenge/executable: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped 
```

`checksec` output: 
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
Some useful comments: 
1. **Full RELRO**: Overwriting the GOT is not a viable approach
2. **Canary Found**: Overwriting a return address may require discovering a vulnerability to leak, brute force, or skip over the canary
3. **PIE Enabled**: Function addresses in the main executable cannot be determined via static analysis
4. **NX Enabled**: Classic stack shellcode injection is not an effective approach

#### Dynamic Analysis

Overflowing the payload buffer and inspecting the stack using `gef`, showed that all but one of the local variables of the `challenge function` were placed "above" the buffer on the stack, which means they cannot be overwritten. 

The local variable that was placed "below" the payload buffer is the variable holding the flag, and therefore it can be read past into.

The payload buffer is located at `[rbp - 0x180]`, and the flag buffer is found to be at `[rbp - 0x178]`

```asm
00401fd3  488d3d2e100000     lea     rdi, [rel data_403008]  {"/flag"}
00401fda  b800000000         mov     eax, 0x0
00401fdf  e87cf1ffff         call    open
00401fe4  89c1               mov     ecx, eax
00401fe6  488b8588feffff     mov     rax, qword [rbp-0x178 {var_180}] 
00401fed  ba00010000         mov     edx, 0x100
00401ff2  4889c6             mov     rsi, rax
00401ff5  89cf               mov     edi, ecx
00401ff7  e844f1ffff         call    read
```

#### Vulnerability

The core issue is that the program lets the user provide an arbitrarily large input size, which far exceeds the size of the payload array, which can be leveraged alongside unsafe string printing behavior to leak the flag.

```asm
00401ffc  488d3d0b100000     lea     rdi, [rel data_40300e]  {"Payload size: "}
00402003  b800000000         mov     eax, 0x0
00402008  e823f1ffff         call    printf
0040200d  488d8578feffff     lea     rax, [rbp-0x188 {var_190}]
00402014  4889c6             mov     rsi, rax {var_190}
00402017  488d3dff0f0000     lea     rdi, [rel data_40301d]
0040201e  b800000000         mov     eax, 0x0
00402023  e848f1ffff         call    __isoc99_scanf
00402028  488b8578feffff     mov     rax, qword [rbp-0x188 {var_190}]
0040202f  4889c6             mov     rsi, rax
00402032  488d3def0f0000     lea     rdi, [rel data_403028]  {"Send your payload (up to %lu bytes)!\n"}
00402039  b800000000         mov     eax, 0x0
0040203e  e8edf0ffff         call    printf
00402043  488b9578feffff     mov     rdx, qword [rbp-0x188 {var_190}]
0040204a  488b8580feffff     mov     rax, qword [rbp-0x180 {payload_buffer]
00402051  4889c6             mov     rsi, rax
00402054  bf00000000         mov     edi, 0x0
00402059  e8e2f0ffff         call    read
```
As can be seen here, there is no protective size check and the payload input can be large enough to overwrite data on the stack. 

After the user enters the payload, it is displayed using `printf` and formatted using `%s`
```asm
00402099  488b8580feffff     mov     rax, qword [rbp-0x180 {payload_buffer}]
004020a0  4889c6             mov     rsi, rax
004020a3  488d3dca0f0000     lea     rdi, [rel data_403074]  {"You said: %s\n"}
004020aa  b800000000         mov     eax, 0x0
004020af  e87cf0ffff         call    printf
004020b4  488d3dc70f0000     lea     rdi, [rel data_403082]  {"Goodbye!"}
004020bb  e850f0ffff         call    puts
```
The `%s` format specifier will continue reading until it encounters a null character. 

Using this piece of information along with:
1. An arbitrarily large payload string can be entered
2. The flag is "below" the payload buffer on the stack

An exploit can be developed to leak the flag.

#### Exploit Implementation
We can make the payload string large enough that it reaches the beginning of the flag and so the flag will become a part of the formatted string. 

To ensure a null byte is not entered at the end of the payload string, which would prevent `printf` from reading past the end of the payload, we can write a pwntools script to send a byte string. 

Here's  how it was used in the exploit: 
```py
import pwn

p = pwn.process("/challenge/executable")
# ... 
p.sendline(b"A" * PAYLOAD_SIZE)
```

Additional dynamic analysis will have to be performed in order to determine memory offsets which will let you determine the required payload size.

#### Defense Discussion
In cases where the user sends in input, you must always ensure that there are size checks in place to prevent buffer overflows.

In the case of this program, it would look something like this:
```c
int payload_size;
printf("Payload size: "); 
scanf("%d", &payload_size); 

if (payload_size > MAX_SIZE) {
	fprintf(stderr, "Payload size too large\n"); 
	exit(-1);
}
```

