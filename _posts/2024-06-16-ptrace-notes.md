---
title: "Notes about Linux ptrace syscall"
excerpt: "My personal notes about the Linux ptrace syscall"
categories:
    - Reverse Engineering
    - Linux
tags:
    - ELF
    - Linux
    - Binary Analysis
    - POSIX
last_modified_at: 2024-06-16-14:55:00
toc: true
---

# ptrace

this system call is highly used when analyzing, debugging, reverse engineering, and modifying programs that use *ELF* format. *ptrace* allows us to attach to a process and access code, data, stack, heap, and registers.

Once *ELF* is completely mapped, we can attach to process, parse or modify *ELF* similarly as we do in file on disk. *ptrace* gives access the program instead of using *open/mmap/read/write* calls.

*ptrace* gives full control over program's execution flow, this allows memory virus infection, virus analysis or even detection of userland memory rootkits, hotpatching, reverse engineering.

## Importance of ptrace

Someone can attach to a process that they own and modify, analyze, reverse, and debug it. *gdb*, *strace*, and *ltrace* make use of *ptrace*. It gives a programmer ability to attach to a process and modify the memory, which can include injecting and modifying data structures such as **Global Offset Table (GOT)** for shared library redirection.

## ptrace requests

*ptrace* system call has a *libc* wrapper, you may include *ptrace.h* and call *ptrace* while passing it a request and a process ID.

```c
#include <sys/ptrace.h>

long ptrace(enum __ptrace_request request, pid_t pid,
void *addr, void *data);
```

## Request Types (enum __ptrace_request)

| Request | Description |
|:-------:|:------------|
| *PTRACE_ATTACH* | Attach to process specified by *pid*, making it a tracee of calling process. Tracee is sent a *SIGSTOP* signal, but will not have stopped by completion of this call. Use *waitpid* to wait for tracee to stop. |
| *PTRACE_TRACEME* | Indicates this process is to be traced by its parent. A process shouldn't make this if its parent isn't expecting to trace it. |
| *PTRACE_PEEKTEXT* *PTRACE_PEEKDATA* *PTRACE_PEEKUSER* | Allow tracing process to read from a virtual memory address within traced process image; we can read entire text or data segment into a buffer for analysis. No difference in implementation between these requests. |
| *PTRACE_POKETEXT* *PTRACE_POKEDATA* *PTRACE_POKEUSER* | Requests allow tracing process to modify any location within traced process image. |
| *PTRACE_GETREGS* | Allows tracing process to get a copy of traced process's registers. Each thread context has its own register set. |
| *PTRACE_SETREGS* | Allows tracing process to set new register values for traced process, allowing modifying for example instruction pointer, to point a shellcode |
| *PTRACE_CONT* | Tells stopped traced process to resume execution |
| *PTRACE_DETACH* | resumes traced process and detaches from it |
| *PTRACE_SYSCALL* | Request resumes traced process but arranges for it to stop at entrance/exit of next syscall. Allows us to inspect arguments for syscall and even modify them. *ptrace* request heavily used in code for a program called *straced*, which traces all system calls when a program runs |
| *PTRACE_SINGLESTEP* | Resumes process but stops it after next instruction. Single stepping allows a debugger to stop after every instruction executed. Allows a user to inspect values of registers and state of process after each instruction |
| *PTRACE_GETSIGINFO* | Retrieves information about signal that caused the stop. It retrieves a copy of *siginfo_t* structure, this can be modified and set (with next request) |
| *PTRACE_SETSIGINFO* | Sets signal information. This will affect only signals that would normally be delivered to tracee and would be caught by the tracer (*addr* ignored) |
| *PTRACE_SETOPTIONS* | sets *ptrace* options from *data* (*addr* ignored). Data is interpreted as a bitmask of options. |


Two terms:
* *tracer* process doing the tracing (invoking *ptrace*).
* *tracee* or *traced*: program being traced by tracer.

## The process register state and flags

Depending on the architecture we are going to trace we're gonna have different struct of registers, but mainly we will have general-purpose registers, segmentation registers, stack pointer, CPU flags, and TLS registers:

**x86-64**

```c
struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
```

**x86-32**

```c
struct user_regs_struct
{
  long int ebx;
  long int ecx;
  long int edx;
  long int esi;
  long int edi;
  long int ebp;
  long int eax;
  long int xds;
  long int xes;
  long int xfs;
  long int xgs;
  long int orig_eax;
  long int eip;
  long int xcs;
  long int eflags;
  long int esp;
  long int xss;
};
```

**Notes**

The structure contains an *orig_eax* which contains in a syscall the number of the syscall, this can be used in the entry or the exit of a syscall to know the syscall number.
In Linux to search for the **thread-local-storage (TLS)** we must use the register *%gs* in 32 bits, and *%fs* in 64 bits.

## Implementing a simple Debugger

Complete code is in *ptrace_debugger.c*, we'll see here the most important parts of the equation.

This code only works on binaries of 64 bits for Intel, and compiled as executables, so no code in the form of PIC or PIE is found (all the virtual addresses in the segments are absolute addresses, not relative virtual addresses). So the first part of the program just retrieves the program name and a function to set a breakpoint:

```c
if ((h.exec = strdup(argv[1])) == NULL)
{
    perror("executable strdup");
    exit(-1);
}
args[0] = h.exec;
args[1] = NULL;

if ((h.symname = strdup(argv[2])) == NULL)
{
    perror("symname strdup");
    exit(-1);
}
```

All the data is stored in a structure developed for the program.

Then, file is read into a buffer and parsed with ELF structures, the only part we'll see from here will be the check done to the binary in order to debug it or not. The first check is done to know if is a 64 bit binary:

```c
if (h.ehdr->e_machine != EM_IA_64 && h.ehdr->e_machine != EM_X86_64)
{
    fprintf(stderr, "Only supported x86_64 elf binaries\n");
    exit(-2);
}
```

Second one is to know if binary is an EXE, or other type of binary (it could be a DYN for example). Only those compiled without PIE will be allowed:

```c
if (h.ehdr->e_type != ET_EXEC)
{
    fprintf(stderr, "%s is not an ELF executable\n", h.exec);
    exit(-1);
}
```

Finally, we will check for symbol strings, and sections (in order to retrieve symbols), this is done to retrieve the address of the function we gave as parameter:

```c
if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0)
{
    fprintf(stderr, "Section header table not found\n");
    exit(-1);
}

if ((h.symaddr = lookup_symbol(&h, h.symname)) == 0)
{
    fprintf(stderr, "Unable to find symbol: %s not found in executable\n", h.symname);
    exit(-1);
}
```

**How to implement tracer and tracee**

Two different implementations can be done to create both tracer and tracee, both implementations start by the same code, create a child process, this can be done using the syscall *fork*, syscall creates a child process as a copy of the parent from the beginning of the code to that moment, for child process it returns a value 0, and for parent process return other value greater than 0, which represent the pid of child process.

* Unusual implementation: in this implementation the parent process is the tracee, and the child process is the tracer. Parent process can do the next:

```c
prctl(PR_SET_PTRACER, child_pid, 0, 0, 0);
sleep(X);
```

So in this case, the parent process tells specifically that its child process can trace it, and sleep some time until child process attach to it.

The child process, must receive the parent process PID in order to call *PTRACE_ATTACH*.

```
ptrace(PTRACE_ATTACH, parent_process, 0x0, 0x0);
```

This will not be in any case, the way that we will implement it is the next.

* Implementation we will use: in this case, is the most common way for the implementation, the parent process will trace the child process. The child process will execute *ptrace* to indicate that it will be traced by parent process, and parent process will wait for child process.

First of all create the process with *fork*:

```c
if ((pid = fork()) < 0)
{
    perror("fork");
    exit(-1);
}
```

Then we will have the check for the child process and the execution of the binary given as argument:

```c
if (pid == 0) // child process
{
    if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) // ptrace own 
    // process (will be catched by parent process)
    {
        perror("PTRACE_TRACEME");
        exit(-1);
    }

    execve(h.exec, args, envp); // execute new process, 
    // never return (this is like creating a process 
    // suspended in windows)
    exit(0);
}
```

That code represent all that child process will do in the binary.

Now parent process will wait for child process, nothing more.

```c
wait (&status);
```

As we gave as input one of the functions, we will set a breakpoint on that function, previously we obtained the address of the function through the binary symbols, the process to set a breakpoint is to read the address where we gonna set the breakpoint so we will have the original byte to restore it later, and we will set the trap byte. A software breakpoint is implemented using the byte *0xCC* once the program is gonna execute an instruction with this byte (instruction *int 3*) it will generate an exception, that exception will be catched by parent process (and we should know that it has been generated in the address of the breakpoint).

```c
// read address where to write breakpoint
if ((unsigned int)(orig = ptrace(PTRACE_PEEKTEXT, pid, 
h.symaddr, NULL)) < 0)
{
    perror("PTRACE_PEEKTEXT");
    exit(-1);
}

// set software interruption
trap = (orig & ~0xff) | 0xcc;

// write instruction with breakpoint
// again into same address
if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0)
{
    perror("PTRACE_POKETEXT");
    exit(-1);
}
```

Once with breakpoint set, and in order to continue process execution we will call again ptrace and we will wait for a new event:

```c
if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
{
    perror("PTRACE_CONT");
    exit(-1);
}

wait(&status);
```

The child process will continue, and in the moment that the chosen function is executed, the breakpoint will halt the process and will wake up the parent process from the wait. This will return in the status the reason, we can check the reason with different macros, in here we will use *WIFSTOPPED* to check if child is stopped, and with *WSTOPSIG* we will check the stop status, the reason should be **SIGTRAP**.

```c
if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
{
```

We can now get the register values using one of the previous structures depending on the architecture:

```c
if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0)
{
    perror("PTRACE_GETREGS");
    exit(-1);
}
```

Once the breakpoint has halt the program, we have to follow various steps in order to:

* recover the original byte from the instruction.
* fix the program counter to point again to the original instruction.
* execute only that instruction.
* set breakpoint again.
* continue the execution.

```c
// write the original byte again back to the address
if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, orig) < 0)
{
    perror("PTRACE_POKETEXT");
    exit(-1);
}

// fix the program counter, so point again to the instrucction
h.pt_reg.rip = h.pt_reg.rip - 1;

// Set the values back to the process
if (ptrace(PTRACE_SETREGS, pid, NULL, &h.pt_reg) < 0)
{
    perror("PTRACE_SETREGS");
    exit(-1);
}

// Execute only one instrucction (the one fixed)
if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
{
    perror("PTRACE_SINGLESTEP");
    exit(-1);
}

// wait for single step
wait(NULL);

// restore software breakpoint byte
if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0)
{
    perror("PTRACE_POKETEXT");
    exit(-1);
}
```

Finally we should jump to the *PTRACE_CONT* *ptrace* call.


## Implementing an attacher debugger

In some cases we do want to attach to an already running process. In that case, we need to get the pid of the process we want to attach to. This time we have the code in *ptrace_attacher.c*. The code is similar to the previous one, but this time we will need code to get the pid, and also to get the path of the binary in order to parse it and detect if it's an EXE file of 64 bits.

So this time, we will have a switch statement in order to detect if the user is giving a pid or exe file (as it can debug both this program), and also to get the function name. To do that, we will use the *getopt* function:

```c
while ((c = getopt(argc, argv, "p:e:f:")) != -1)
{
    switch(c)
    {
    case 'p':
        pid = atoi(optarg);
        h.exec = get_exe_name(pid);
        if (h.exec == NULL)
        {
            printf("Unable to retrieve executable path for pid: %d\n", pid);
            exit(-1);
        }
        mode = PID_MODE;
        break;
    case 'e':
        if ((h.exec = strdup(optarg)) == NULL)
        {
            perror("strdup");
            exit(-1);
        }

        mode = EXE_MODE;
        break;
    case 'f':
        if ((h.symname = strdup(optarg)) == NULL)
        {
            perror("strdup");
            exit(-1);
        }
        break;
    default:
        printf("Unknown option\n");
        break;
    }
}
```

If pid is given instead of exe, the next code is executed in order to retrieve the exe path from the command line. This is possible in Linux thanks to the path */proc/<pid>/cmdline*, this would be the code of *get_exe_name*:

```c
char*
get_exe_name(int pid)
{
	char cmdline[255], path[512], *p;
	int fd;
	snprintf(cmdline, 255, "/proc/%d/cmdline", pid);

	if ((fd = open(cmdline, O_RDONLY)) < 0)
	{
        fprintf(stderr, "Error opening file %s\n", cmdline);
		perror("open");
		exit(-1);
	}

	if (read(fd, path, 512) < 0)
	{
		perror("read");
		exit(-1);
	}

	if ((p = strdup(path)) == NULL)
	{
		perror("strdup");
		exit(-1);
	}

	return p;
}
```

As we will attach to the program, we will set a handler for keyboard codes as *CTRL+C*, this handler is set with a call to the function **signal** giving as first parameter the signal to handle (in this case **SIGINT**) and as second parameter the function. In this function what we would do is to *dettach* from the traced process:

```c
void 
sighandler(int sig)
{
	printf("Caught SIGINT: Detaching from %d\n", global_pid);
	if (ptrace(PTRACE_DETACH, global_pid, NULL, NULL) < 0 && errno)
	{
		perror("PTRACE_DETACH");
		exit(-1);
	}

	exit(0);
}
```

Once we obtain the path to the binary, the process is pretty similar to the previous one, we have to parse the binary, and obtain the address of the function from the symbol table of the binary, it could be that no symbol table is present, so execution could not be possible as in this case we rely on the symbols.

Next step will be easier than in previous case, so in previous debugger we had to create another process to trace it, this time we have to attach to the remote process by pid:

```c
// attach to process 'pid'
if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
{
    perror("PTRACE_ATTACH");
    exit(-1);
}
// finally wait for the other process to stop
wait(&status);
```

The next steps would be exactly the same than in the debugger, as the only part a little bit different is the use of **PTRACE_ATTACH** instead of using the **PTRACE_TRACEME** in the child process.

## Useful Functions

### Read Function

Due to the fact that the **ptrace** call only reads in words with **PTRACE_PEEKDATA**, so in 32 bits we should for example read in blocks of 4 bytes, in case that we need to read an unaligned size of bytes, we can use the next function:

```c
long * read_data_from_memory(pid_t pid,long *addr,long *buffer,size_t size)
{
  size_t size_cpy;
  long read_value;
  uint last_value;
  long remainder;
  int i;
  uint mask_byte;
  
  size_cpy = size;
  if ((int)size < 0) {
    size_cpy = size + 3;
  }
  i = 0;
  while (i < (int)size_cpy >> 2) {
    // read from remote process
    read_value = ptrace(PTRACE_PEEKDATA,pid,addr,0x0);
    *buffer = read_value;
    addr = addr + 1;
    buffer = buffer + 1;
    i = i + 1;
  }

  /* If size is not aligned to long (4)
    read the last part as byte, 2 bytes 
    or 3 bytes */

  remainder = size % sizeof(long);

  if (remainder == 0x1) {
    mask_byte = 0xff;
  }
  if (remainder == 0x2) {
    mask_byte = 0xffff;
  }
  if (remainder == 0x3) {
    mask_byte = 0xffffff;
  }
  if (remainder != 0x0) {
    last_value = ptrace(PTRACE_PEEKDATA,pid,addr, 0x0);
    *buffer = *buffer & ~mask_byte | last_value & mask_byte;
  }
  
  return remainder;
}
```

### Write Function

The same happen with the Write function so we have to go in rounds of 4 bytes (size of long), instead of using **PTRACE_PEEKDATA** to retrieve data (it will be used at the end), we will use **PTRACE_POKEDATA**:

```c
void write_in_memory(pid_t current_pid,long *address,void **buffer,size_t size)
{
  long last_value;
  size_t size_cpy;
  int remainder;
  int i;
  uint mask;
  
  size_cpy = size;
  if ((int)size < 0) {
    size_cpy = size + 3;
  }
  i = 0;
  while (i < (int)size_cpy >> 2) {
    ptrace(PTRACE_POKEDATA,current_pid,address,*buffer);
    address = address + 1;
    buffer = buffer + 1;
    i = i + 1;
  }


  remainder = size % sizeof(long);

  if (remainder == 1) {
    mask = 0xff;
  }
  if (remainder == 2) {
    mask = 0xffff;
  }
  if (remainder == 3) {
    mask = 0xffffff;
  }

  if (remainder != 0) {
    last_value = ptrace(PTRACE_PEEKDATA,current_pid,address, 0x0);
    ptrace(PTRACE_POKEDATA,current_pid,address,
                     (void *)((uint)*buffer & mask | ~mask & last_value));
  }
  
  return;
}
```

### Avoid Tracing From Other Programs

In the same way that **ptrace** can be used to trace/debug a program and get its state while running, it's possible to trick **ptrace** to avoid other processes to execute ptrace on a given process. So if we call **ptrace** with **PTRACE_ATTACH** giving as pid our own pid, we will set our own process as the tracer.

```c
current_pid = getpid();

ptrace_output = ptrace(PTRACE_ATTACH, current_pid, 0x0, 0x0);

if (ptrace_output == -1)
{
    puts("Detected a tracer already attached, killing process\n");
    kill(current_pid, 9);
}
```

Also, in case we want to detect if a tracer is already attached to us, we can get its pid from one of the files in */proc/<our_pid>/status*, checking line by line, we will find one that start by *"TracerPid"*, reading that line and extracting the value we will get if there's no process tracing us (0) or if there's one process tracing us (pid of tracert):

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_LEN 256

int
GetTracerPidValue(pid_t current_pid)
{
    const char *proc_status = "/proc/%d/status";
    const char *tracerpid = "TracerPid:";
    const char *tracerpid_value = "TracerPid: %d";

    char proc_pid_status[MAX_LEN];
    FILE *fd;
    char *line_buf;
    size_t line_buf_size;
    ssize_t line_size;
    int tracerpid_found;
    size_t tracerpid_len;
    int tracerpid_value_int;

    memset(proc_pid_status, 0, MAX_LEN);

    snprintf(proc_pid_status, MAX_LEN, proc_status, current_pid);
    fd = fopen(proc_pid_status, "r");

    line_buf = NULL;
    line_buf_size = 0;
    tracerpid_found = 0;

    do
    {
        line_size = getline(&line_buf, &line_buf_size, fd);
        if (line_size < 0)
        {
            free(line_buf);
            fclose(fd);
            return 0;
        }
        tracerpid_len = strlen(tracerpid);
        tracerpid_found = memcmp(tracerpid, line_buf, tracerpid_len);
    } while (tracerpid_found != 0);

    sscanf(line_buf, tracerpid_value, &tracerpid_value_int);
    free(line_buf);
    fclose(fd);

    return tracerpid_value_int;
}


int
main()
{
    int tracerpid = GetTracerPidValue(getpid());
    
    if (tracerpid != 0)
    {
        printf("Debugger detected, debugger's pid %d\n", tracerpid);
        return -1;
    }
    else
        printf("No debugger detected, all fine\n");

    return 0;
}
```

### Managing Syscalls

Whenever you want to manage the syscalls in a program you're tracing, we saw that it's possible to stop in these syscalls using the flag **PTRACE_SYSCALL** in the **ptrace** function, this works similar to **PTRACE_CONT** but when a syscall is executed this will stop at the beginning of the syscall, and with another **PTRACE_SYSCALL** the program will stop at the end of the syscall.

Due to the fact that when a syscall is executed, the registers are modified, we need some way in order to know which syscall is going to be executed, for that reason in the structures of registers, we have an specific one with this number, if we know from assembly programming, the syscall number is set in *eax* or *rax* depending on the architecture, well, in the structures we have a field like *orig_eax* or *orig_rax*, these value holds the syscall number. Finally, once a syscall has finished we will have the return value in *eax* or *rax*.

To handle the syscall, it will be the same method than handling a breakpoint, we will have a **SIGSTOP**, and the reason will be a **SIGTRAP**. If we have a list of breakpoints, we should retrieve the value from the program counter (*eip* or *rip*) in order to check if that value - 1 (because the program counter holds the next instruction) is one of our breakpoint addresses. Also other way would be to read the program counter value - 1 memory and check if it contains a *0xCC* (software breakpoint), in that case handle the breakpoint as we saw previously and nothing more.

In order to know if we are at the beginning of a syscall or at the end, we can just use a "boolean" value with 1 and 0, these would be an example:

```c
if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
{
    // get registers from program
    if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0)
    {
        perror("PTRACE_GETREGS");
        exit(-1);
    }

    if (h.pt_reg.rip != (h.symaddr+1))
    {
        if (is_entry)
        {
            printf("Stop in a syscall, number of syscall: %d\n", h.pt_reg.orig_rax);
            is_entry = 0;
        }
        else
        {
            printf("End of syscall, returns: %016x\n", h.pt_reg.rax);
            is_entry = 1;
        }
    }
```

If you remember in *h.symaddr* we had the address of the function where we set the breakpoint, this is just a simple way to manage the syscall.

**How to avoid the execution of a syscall**

As written by [nullprogram](https://nullprogram.com/blog/2018/06/23/) we can block the execution of the syscall, setting the *orig_eax* or *orig_rax* value to *-1* as the syscall has not been executed yet at the entry of the syscall, finally, once the syscall finish, we just set in *eax* or *rax* the value *-EPERM* so the operation is not permitted:

```c
for (;;) {
    /* Enter next system call */
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, 0, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    /* Is this system call permitted? */
    int blocked = 0;
    if (is_syscall_blocked(regs.orig_rax)) {
        blocked = 1;
        regs.orig_rax = -1; // set to invalid syscall
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
    }

    /* Run system call and stop on exit */
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, 0, 0);

    if (blocked) {
        /* errno = EPERM */
        regs.rax = -EPERM; // Operation not permitted
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
    }
}
```

In the previous code, we would check for a given syscall if it appears in a blacklist. In the moment before returning we can return another value if we want to emulate for example some behavior.


### Managing Exceptions

With ptrace we can also manage exceptions as we did with the breakpoints and the syscalls, to do that we will have to check for a stop reason equals to **SIGSEGV**, inside of that code, we can get a structure of the exception with **PTRACE_GETSIGINFO**, in here we can get the address where the exception happened, reason, and so on. Let's going to see an example of code:

```c
if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
{
    siginfo_t siginfo;

    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) < 0)
    {
        perror("PTRACE_GETSIGINFO");
        exit(-1);
    }

    // get registers from program
    if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0)
    {
        perror("PTRACE_GETREGS");
        exit(-1);
    }
    
    
    printf("siginfo.si_addr: 0x%08lx\n", siginfo.si_addr);
    printf("Exception in address: 0x%lx\n", h.pt_reg.rip);

    printf("%%rcx: %016x\t%%rdx: %016x\t%%rbx: %016x\n"
                "%%rax: %016x\t%%rdi: %016x\t%%rsi: %016x\n"
                "%%r8:  %016x\t%%r9:  %016x\t%%r10: %016x\n"
                "%%r11: %016x\t%%r12: %016x\t%%r13: %016x\n"
                "%%r14: %016x\t%%r15: %016x\t%%rsp: %016x\n"
                "%%rbp: %016x\n",
                h.pt_reg.rcx, h.pt_reg.rdx, h.pt_reg.rbx,
                h.pt_reg.rax, h.pt_reg.rdi, h.pt_reg.rsi,
                h.pt_reg.r8, h.pt_reg.r9, h.pt_reg.r10,
                h.pt_reg.r11, h.pt_reg.r12, h.pt_reg.r13,
                h.pt_reg.r14, h.pt_reg.r15, h.pt_reg.rsp,
                h.pt_reg.rbp);
}
```

# Appendix

## Flare-on challenge code

Next is a code from a Flare-on challenge from a few years ago (obtained from the decompilation using Ghidra). There were two "debuggers" implemented, next the code shows the first and the second debugger implemented

### First Debugger

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // Posix header
#include <fcntl.h>
#include <errno.h>  // Standard errors
#include <signal.h> // Unix signals
#include <elf.h>    // ELF headers
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>   // file stats
#include <sys/ptrace.h> // ptrace debugging syscall
#include <sys/mman.h>   // memory mapping

/* This function directly loads libc.so.6
   and the function ptrace, instead of relying
   on PLT/GOT.
   Call to ptrace */

long call_real_ptrace(__ptrace_request request, pid_t pid, void *addr, void *data)
{
  void *libc_so_6;
  ptrace *ptrace;
  long ptrace_return;

  libc_so_6 = (void *)dlopen("libc.so.6", 1);
  ptrace = (ptrace *)dlsym(libc_so_6, "ptrace");
  ptrace_return = (*ptrace)(request, pid, addr, data);
  return ptrace_return;
}

long *read_data_from_memory(pid_t pid, long *addr, long *buffer, size_t size)

{
  size_t size_cpy;
  long read_value;
  uint last_value;
  long remainder;
  int i;
  uint mask_byte;

  size_cpy = size;
  if ((int)size < 0)
  {
    size_cpy = size + 3;
  }
  i = 0;
  while (i<(int)size_cpy> > 2)
  {
    read_value = call_real_ptrace(PTRACE_PEEKDATA, pid, addr, (void *)0x0);
    *buffer = read_value;
    addr = addr + 1;
    buffer = buffer + 1;
    i = i + 1;
  }
  /* If size is not aligned to long (4)
                       read the last part as byte, 2 bytes or 3 bytes */

  remainder = size % sizeof(long);

  if (remainder == 0x1)
  {
    mask_byte = 0xff;
  }
  if (remainder == 0x2)
  {
    mask_byte = 0xffff;
  }
  if (remainder == 0x3)
  {
    mask_byte = 0xffffff;
  }
  if (remainder != 0x0)
  {
    last_value = call_real_ptrace(PTRACE_PEEKDATA, pid, addr, (void *)0x0);
    *buffer = *buffer & ~mask_byte | last_value & mask_byte;
  }

  return remainder;
}

void write_in_memory(pid_t current_pid, long *address, void **buffer, size_t size)

{
  long last_value;
  size_t size_cpy;
  int remainder;
  int i;
  uint mask;

  size_cpy = size;
  if ((int)size < 0)
  {
    size_cpy = size + 3;
  }
  i = 0;
  while (i<(int)size_cpy> > 2)
  {
    call_real_ptrace(PTRACE_POKEDATA, current_pid, address, *buffer);
    address = address + 1;
    buffer = buffer + 1;
    i = i + 1;
  }

  remainder = size % sizeof(long);

  if (remainder == 1)
  {
    mask = 0xff;
  }
  if (remainder == 2)
  {
    mask = 0xffff;
  }
  if (remainder == 3)
  {
    mask = 0xffffff;
  }

  if (remainder != 0)
  {
    last_value = call_real_ptrace(PTRACE_PEEKDATA, current_pid, address, (void *)0x0);
    call_real_ptrace(PTRACE_POKEDATA, current_pid, address,
                     (void *)((uint)*buffer & mask | ~mask & last_value));
  }

  return;
}

int GetTracerPidValue(__pid_t current_pid)
{
  size_t tracerpid_len;
  int tracerpid_found;
  int iVar1;
  undefined4 *puVar2;
  int in_GS_OFFSET;
  char *line_buf;
  size_t line_buf_size;
  int tracerpid_value_int;
  FILE *fd;
  __ssize_t line_size;
  char Tracerpid[11];
  char Tracerpid_value[14];
  char proc_status[16];
  undefined4 proc_pid_status[64];
  int COOKIE;

  COOKIE = *(int *)(in_GS_OFFSET + 0x14);
  iVar1 = 0x40;
  puVar2 = proc_pid_status;
  while (iVar1 != 0)
  {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  proc_status[0] = '/';
  proc_status[1] = 'p';
  proc_status[2] = 'r';
  proc_status[3] = 'o';
  proc_status[4] = 'c';
  proc_status[5] = '/';
  proc_status[6] = '%';
  proc_status[7] = 'd';
  proc_status[8] = '/';
  proc_status[9] = 's';
  proc_status[10] = 't';
  proc_status[11] = 'a';
  proc_status[12] = 't';
  proc_status[13] = 'u';
  proc_status[14] = 's';
  proc_status[15] = '\0';
  Tracerpid[0] = 'T';
  Tracerpid[1] = 'r';
  Tracerpid[2] = 'a';
  Tracerpid[3] = 'c';
  Tracerpid[4] = 'e';
  Tracerpid[5] = 'r';
  Tracerpid[6] = 'P';
  Tracerpid[7] = 'i';
  Tracerpid[8] = 'd';
  Tracerpid[9] = ':';
  Tracerpid[10] = '\0';
  Tracerpid_value[0] = 'T';
  Tracerpid_value[1] = 'r';
  Tracerpid_value[2] = 'a';
  Tracerpid_value[3] = 'c';
  Tracerpid_value[4] = 'e';
  Tracerpid_value[5] = 'r';
  Tracerpid_value[6] = 'P';
  Tracerpid_value[7] = 'i';
  Tracerpid_value[8] = 'd';
  Tracerpid_value[9] = ':';
  Tracerpid_value[10] = ' ';
  Tracerpid_value[11] = '%';
  Tracerpid_value[12] = 'd';
  Tracerpid_value[13] = '\0';
  sprintf((char *)proc_pid_status, proc_status, current_pid);
  fd = fopen((char *)proc_pid_status, (char *)&BYTE_0805695c);
  line_buf = (char *)0x0;
  line_buf_size = 0;
  do
  {
    /* This breaks on the debugger probably because
                       a TOCTOU error, the file is deleted before
                       the process can access it. */
    line_size = getline(&line_buf, &line_buf_size, fd);
    if (line_size == -1)
    {
      free(line_buf);
      fclose(fd);
      tracerpid_value_int = 0;
      goto LAB_0804bfd7;
    }
    tracerpid_len = strlen(Tracerpid);
    tracerpid_found = memcmp(Tracerpid, line_buf, tracerpid_len);
  } while (tracerpid_found != 0);
  __isoc99_sscanf(line_buf, Tracerpid_value, &tracerpid_value_int);
  free(line_buf);
  fclose(fd);
LAB_0804bfd7:
  if (COOKIE != *(int *)(in_GS_OFFSET + 0x14))
  {
    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return tracerpid_value_int;
}

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void first_debugger(__pid_t parent_process)
{
  long ptrace_Return;
  __pid_t _Var1;
  void *value_0x9e3779b9;
  size_t sVar2;
  char *pcVar3;
  char chmod_pathname[248];
  uint wstatus;
  uint crc64_first_dword;
  uint crc64_second_dword;
  byte file_to_truncate[16000];
  user_regs_struct32 regs;
  uint wstatus2;
  uint check_WSTOPPED;
  uint check_SIGSTOP;
  uint check_SIGTRAP;
  uint check_SIGILL;
  uint check_SIGSEGV;
  uint local_74;
  uint local_70;
  uint local_6c;
  uint wstatus_cpy;
  uint local_64;
  void *parameter_2_value_incremented;
  void *parameter_2;
  long parameter_1;
  long address_exception;
  long stack_esp;
  void **buffer_to_write;
  size_t len_buffer_to_write;
  void **string_decrypted;
  int obfuscated_syscall;
  uint bytes_from_syscall;
  int *paddress_to_write;
  void *exit_status;
  int tracerpid_value;
  code *p_zero;
  int i;
  long index_different;
  long incremental_value;

  p_zero = (code *)0x0;
  /* try to attach to parent
       if ptrace_Return == -1: parent has died already or gdb is attached to parent.
       else: parent is attacheable */
  ptrace_Return = call_real_ptrace(PTRACE_ATTACH, parent_process, (void *)0x0, (void *)0x0);
  if (ptrace_Return == -1)
  {
    /* No tracing allowed!!!
           Check if parent process has a PID
           in TracerPid. */
    tracerpid_value = GetTracerPidValue(parent_process);
    if (tracerpid_value == 0)
    {
      /* No tracer found, error, abort mission */
      puts("OOPSIE WOOPSIE!! Uwu We made a mistaky wakey!!!!");
      kill(parent_process, 9);
    }
    else
    {
      /* Try to attach to debugger of parent process */
      ptrace_Return = call_real_ptrace(PTRACE_ATTACH, tracerpid_value, (void *)0x0, (void *)0x0);
      if (ptrace_Return == -1)
      {
        /* Kill my parent debugger and myself */
        kill(tracerpid_value, 9);
        kill(parent_process, 9);
      }
      else
      {
        while (_Var1 = waitpid(tracerpid_value, (int *)&wstatus, 0), _Var1 != -1)
        {
          wstatus_cpy = wstatus;
          if (WIFSTOPPED(wstatus))
          {
            local_64 = wstatus;
            exit_status = WSTOPSIG(wstatus2);
            if ((exit_status == SIGSTOP) || (exit_status == SIGCHLD))
            {
              call_real_ptrace(PTRACE_CONT, tracerpid_value, 0x0, 0x0);
            }
            else
            {
              call_real_ptrace(PTRACE_CONT, tracerpid_value, 0x0, exit_status);
            }
          }
        }
      }
    }
  }
  else
  {
    /* Set breakpoint after waitpid and continue before fork
           so it's possible to attach to parent and waitpid */
    _Var1 = waitpid(parent_process, (int *)&wstatus2, 0);
    if (_Var1 != -1)
    {
      /* set first 4 bytes of compare_false_flag to
               0f 0b 00 00, in parent process */
      ptrace_Return =
          call_real_ptrace(PTRACE_POKEDATA, parent_process, compare_false_flag, (void *)0xb0f);
      if (ptrace_Return == -1)
      {
        /* WARNING: Subroutine does not return */
        exit(0);
      }
      /* set killl_process_call_function as handler for signal 0xe */
      signal(SIGALRM, kill_process_call_function);
      _Var1 = getpid();
      create_third_process(_Var1);
      paddress_to_write = (int *)&address_to_write;
      _address_to_write = 0;
      /* macOS anti-debug technique
               
            (https://cardaci.xyz/blog/2018/02/12/a-macos-anti-debug-technique-using-ptrace/)
                */
      call_real_ptrace(PT_DENY_ATTACH, parent_process, (void *)0x0, (void *)0x0);
      while (_Var1 = waitpid(parent_process, (int *)&wstatus2, 0), _Var1 != -1)
      {
        /* analyze WSTOPPED reasons, check ptrace documentation
                   analysis of SIGSTOP, SIGTRAP, and so on */
        check_WSTOPPED = wstatus2;
        if (WIFSTOPPED(wstatus2))
        {
          check_SIGSTOP = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGSTOP)
          {
            /* SIGSTOP send, someone trying to attach parent process, deny attach */
            call_real_ptrace(PT_DENY_ATTACH, parent_process, (void *)0x0, (void *)0x0);
          }
          check_SIGTRAP = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGTRAP)
          {
            /* Syscall-stop analyze the syscall */
            call_real_ptrace(PTRACE_GETREGS, parent_process, (void *)0x0, &regs);
            /* Get first bytes from syscall address, check if
                           debugger has set a breakpoint */
            bytes_from_syscall =
                call_real_ptrace(PTRACE_PEEKDATA, parent_process, (void *)(regs.eip + -1), (void *)0x0);
            if (bytes_from_syscall == 0xffffffff)
            {
              /* WARNING: Subroutine does not return */
              /* Wabalaba dub dub */
              exit(0);
            }
            if ((bytes_from_syscall & 0xff) == 0xcc)
            {
              /* Detected breakpoint, fuck off!!! */
              kill(parent_process, 9);
              /* WARNING: Subroutine does not return */
              exit(0);
            }
            /* get an scramble the original eax (syscall number) */
            obfuscated_syscall = (regs.orig_eax ^ 0xdeadbeef) * 0x1337cafe;
            index_different = -1;
            if (obfuscated_syscall == __NR_pivot_root)
            {
              call_real_ptrace(PTRACE_POKEDATA, parent_process, (void *)regs.ebx, (void *)regs.ecx);
            }
            else
            {
              if (obfuscated_syscall < __NR_pivot_root + 1)
              {
                if (obfuscated_syscall == __NR_getpriority)
                {
                  if (*paddress_to_write < 0)
                  {
                    regs.eax = *paddress_to_write;
                  }
                  else
                  {
                    regs.eax = *paddress_to_write + 0x14;
                  }
                  call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                  *paddress_to_write = 0;
                }
                else
                {
                  if (obfuscated_syscall < __NR_getpriority + 1)
                  {
                    if (obfuscated_syscall == __NR_setpriority)
                    {
                      /* if edx == 0xa4: "This string has no purpose and is merely here to waste your
                      time."
                      if edx == 0xa5: [227, 118, 105, 146, 199, 92, 232, 245, 133, 197, 77, 17, 22,
                      250, 244, 232, 0]
                      if edx = 0xaa: """
                      welcome to the land of sunshine and rainbows!
                      as a reward for getting this far in FLARE-ON, we've decided to make this one
                      soooper easy
                      
                      please enter a password friend :) 
                      " */
                      buffer_to_write = (void **)decrypt_string_by_index(regs.edx);
                      sVar2 = strlen((char *)buffer_to_write);
                      write_in_memory(parent_process, (long *)&address_to_write, buffer_to_write,
                                      sVar2 + 1);
                      *paddress_to_write = -0x81a52a0;
                      free(buffer_to_write);
                      regs.eax = 0;
                      call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                    }
                    else
                    {
                      if (obfuscated_syscall == __NR_read)
                      {
                        /* if debugger detects a call to "read" it calls
                                                   fgets to get user flag in a global variable
                                                   but what is copied to buffer of read, is a decrypted
                                                   string, then eax is set to size of the decrypted string */
                        fgets(flag, 0xff, stdin);
                        /* decrypted = "sorry i stole your input :)" */
                        string_decrypted = (void **)decrypt_string_by_index(0xb8);
                        _buffer_pointer = regs.ecx;
                        sVar2 = strlen((char *)string_decrypted);
                        write_in_memory(parent_process, (long *)regs.ecx, string_decrypted, sVar2);
                        sVar2 = strlen((char *)string_decrypted);
                        regs.eax = sVar2 + 1;
                        call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                      }
                    }
                  }
                  else
                  {
                    if (obfuscated_syscall == __NR_exit)
                    {
                      /* set exit status to 1 */
                      regs.eip = regs.eip + -2;
                      regs.eax = 1;
                      call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                      call_real_ptrace(PTRACE_CONT, parent_process, (void *)0x0, (void *)0x0);
                      /* WARNING: Subroutine does not return */
                      exit(0);
                    }
                    if (obfuscated_syscall == _NR_mlockall)
                    {
                      crc64_first_dword =
                          call_real_ptrace(PTRACE_PEEKDATA, parent_process, (void *)regs.ebx,
                                           (void *)0x0);
                      crc64_second_dword =
                          call_real_ptrace(PTRACE_PEEKDATA, parent_process, (void *)(regs.ebx + 4),
                                           (void *)0x0);
                      incremental_value = 0;
                      while ((crc64_first_dword | crc64_second_dword) != 0)
                      {
                        if ((crc64_first_dword & 1) != 0)
                        {
                          incremental_value =
                              (*p_zero)(INS_INCREMENT, incremental_value, crc64_second_dword);
                        }
                        crc64_first_dword = crc64_first_dword >> 1 | crc64_second_dword << 0x1f;
                        crc64_second_dword = crc64_second_dword >> 1;
                      }
                      regs.eax = incremental_value;
                      call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                    }
                    else
                    {
                      if (obfuscated_syscall == __NR_chmod)
                      {
                        read_data_from_memory(parent_process, (long *)regs.ebx, (long *)chmod_pathname, 0xf8);
                        regs.eax = apply_add_ror_xor_to_values(chmod_pathname, regs.ecx);
                        call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                      }
                    }
                  }
                }
              }
              else
              {
                if (obfuscated_syscall == __NR_ioctl)
                {
                  if (regs.ebx == 0x1337)
                  {
                    /* if file descriptor of ioctl == 0x1337 */
                    buffer_to_write = (void **)decrypt_string_by_index(regs.ecx);
                    write_in_memory(parent_process, (long *)&address_to_write, buffer_to_write,
                                    regs.edx);
                    regs.eax = (long)&address_to_write;
                    call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                  }
                  else
                  {
                    regs.eax = -1;
                    call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                  }
                }
                else
                {
                  if (obfuscated_syscall < __NR_ioctl + 1)
                  {
                    if (obfuscated_syscall == __NR_execve)
                    {
                      /* execve just removes the last '\n' from the string given as
                                               flag, so it does not execute anything */
                      buffer_to_write = (void **)malloc(300);
                      read_size_or_until_0xff(parent_process, (void *)regs.ebx, (char *)buffer_to_write, 300);
                      len_buffer_to_write = strlen((char *)buffer_to_write);
                      if (*(char *)((int)buffer_to_write + (len_buffer_to_write - 1)) == '\n')
                      {
                        call_real_ptrace(PTRACE_POKEDATA, parent_process,
                                         (void *)(len_buffer_to_write + regs.ebx + -1), (void *)0x0);
                      }
                      free(buffer_to_write);
                    }
                    else
                    {
                      if (obfuscated_syscall == __NR_uname)
                      {
                        /* uname set the TEA algorithm:
                                                   sum = 0xC6EF3720;
                                                   delta = 0x9e3779b9 */
                        call_real_ptrace(PTRACE_POKEDATA, parent_process, (void *)regs.ebx,
                                         (void *)TEA_DECRYPTION_SUM);
                        value_0x9e3779b9 =
                            (void *)(*p_zero)(INS_SET_TEA_KEY_SCHEDULE_CONSTANT, 0x1337, 0xcafe);
                        call_real_ptrace(PTRACE_POKEDATA, parent_process, (void *)(regs.ebx + 4),
                                         value_0x9e3779b9);
                      }
                    }
                  }
                  else
                  {
                    if (obfuscated_syscall == __NR_truncate)
                    {
                      read_data_from_memory(parent_process, (long *)regs.ebx, (long *)buffer_file_to_truncate,
                                            40000);
                      i = 0;
                      while ((i < 40000 &&
                              (buffer_file_to_truncate[i] != 0
                               /* file to truncate has been modified in a decrypt_real_flag function */
                               )))
                      {
                        file_to_truncate[i] = buffer_file_to_truncate[i];
                        if ((index_different == -1) &&
                            (file_to_truncate[i] != (&DAT_081a5100)[i]
                             /* check please that file_to_truncate is different than a given array */
                             /* DAT_081a5100 decrypted = "4nD_0f_De4th_4nd_d3strUct1oN_4nd",
                                                           so we would have at least
                                                           w3lc0mE_t0_Th3_l4nD_0f_De4th_4nd_d3strUct1oN_4nd */
                             ))
                        {
                          index_different = i;
                        }
                        i = i + 1;
                      }
                      regs.eax = (*p_zero)(INS_COMPARE_FLAG, flag, index_different);
                      index_different = regs.eax;
                      call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                    }
                    else
                    {
                      if (obfuscated_syscall == __NR_write)
                      {
                        /* Take buffer with size and call directly write for
                                                   writing to stdout */
                        len_buffer_to_write = regs.edx;
                        buffer_to_write = (void **)malloc(regs.edx);
                        read_data_from_memory(parent_process, (long *)regs.ecx, (long *)buffer_to_write,
                                              len_buffer_to_write);
                        write(STDOUT_FILENO, buffer_to_write, len_buffer_to_write);
                        regs.eax = len_buffer_to_write;
                        call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                        free(buffer_to_write);
                      }
                      else
                      {
                        if (obfuscated_syscall == __NR_nice)
                        {
                          /* call to nice what it really does is to
                                                       decrypt a string and write to parent
                                                       process memory */
                          buffer_to_write = (void **)decrypt_string_with_struct(regs.ebx);
                          sVar2 = strlen((char *)buffer_to_write);
                          write_in_memory(parent_process, (long *)&address_to_write, buffer_to_write,
                                          sVar2 + 1);
                          free(buffer_to_write);
                          regs.eax = 0;
                          call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          check_SIGILL = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGILL)
          {
            /* copy flag value into parent process memory
                           and set it as a stack parameter
                           finally redirect first process to a diferent
                           method */
            sVar2 = strlen(flag);
            write_in_memory(parent_process, (long *)flag, (void **)flag, sVar2);
            call_real_ptrace(PTRACE_GETREGS, parent_process, (void *)0x0, &regs);
            stack_esp = regs.esp;
            ptrace_Return =
                call_real_ptrace(PTRACE_POKEDATA, parent_process, (void *)(regs.esp + 4), flag);
            if (ptrace_Return == -1)
            {
              /* WARNING: Subroutine does not return */
              exit(0);
            }
            /* set eip as address to function that calls rm -rf -no-preserve-root */
            regs.eip = (long)function_rm_rf_no_preserve_root;
            call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
          }
          check_SIGSEGV = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGSEGV)
          {
            call_real_ptrace(PTRACE_GETREGS, parent_process, (void *)0x0, &regs);
            address_exception =
                call_real_ptrace(PTRACE_PEEKDATA, parent_process, (void *)regs.esp, (void *)0x0);
            parameter_1 = call_real_ptrace(PTRACE_PEEKDATA, parent_process, (void *)(regs.esp + 4),
                                           (void *)0x0);
            parameter_2 = (void *)call_real_ptrace(PTRACE_PEEKDATA, parent_process,
                                                   (void *)(regs.esp + 8), (void *)0x0);
            ptrace_Return = call_real_ptrace(PTRACE_PEEKDATA, parent_process, parameter_2, (void *)0x0);
            /* take index from function FUN_0804c217 and increment it */
            parameter_2_value_incremented = (void *)(ptrace_Return + 1);
            regs.esp = regs.esp + 4;
            if ((int)parameter_2_value_incremented < 0x10)
            {
              regs.eip = parameter_1;
              call_real_ptrace(PTRACE_POKEDATA, parent_process, parameter_2,
                               parameter_2_value_incremented);
              regs.esp = regs.esp + 0x10;
            }
            else
            {
              regs.eip = address_exception;
            }
            call_real_ptrace(PTRACE_SETREGS, parent_process, (void *)0x0, &regs);
          }
          local_74 = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGINT)
          {
            /* CTRL+C
                           0xbc = I HAVE THE CONCH DON'T INTERRUPT ME
                            */
            pcVar3 = decrypt_string_by_index(0xbc);
            puts(pcVar3);
          }
          local_70 = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGTERM)
          {
            pcVar3 = decrypt_string_by_index(0xa3);
            puts(pcVar3);
          }
          local_6c = wstatus2;
          if (WSTOPSIG(wstatus2) == SIGQUIT)
          {
            /* 0xbe = winners never quit */
            pcVar3 = decrypt_string_by_index(0xbe);
            puts(pcVar3);
          }
          call_real_ptrace(PT_DENY_ATTACH, parent_process, (void *)0x0, (void *)0x0);
        }
      }
    }
  }
  return;
}
```

### Second Debugger

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // Posix header
#include <fcntl.h>
#include <errno.h>  // Standard errors
#include <signal.h> // Unix signals
#include <elf.h>    // ELF headers
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>   // file stats
#include <sys/ptrace.h> // ptrace debugging syscall
#include <sys/mman.h>   // memory mapping

void second_debugger(__pid_t current_pid)
{
    long ptrace_output;
    __pid_t return_waitpid;
    int compare_with_no_flare;
    char i_have_the_conch_dont_interrupt_me[36];
    user_regs_struct32 regs;
    int wstatus;
    int local_2c;
    int local_28;
    uint param2;
    long *param1;
    long instruction;
    long return_inst_addr;
    void *stopsig;

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    signal(SIGINT, (__sighandler_t)SIG_IGN);
    signal(SIGQUIT, (__sighandler_t)SIG_IGN);
    signal(SIGTERM, (__sighandler_t)SIG_IGN);
    /* try to attach itself */
    ptrace_output = call_real_ptrace(PTRACE_ATTACH, current_pid, (void *)0x0, (void *)0x0);
    if (ptrace_output == -1)
    {
        puts("OOPSIE WOOPSIE!! Uwu We made a mistaky wakey!!!!");
        kill(current_pid, 9);
    }
    else
    {
        do
        {
            return_waitpid = waitpid(current_pid, &wstatus, 0);
            if (return_waitpid == -1)
            {
                return;
            }
            local_2c = wstatus;
            /* WIFSTOPPED(wstatus) */
            if (WIFSTOPPED(wstatus))
            {
                local_28 = wstatus;
                /* WEXITSTATUS(wstatus) */
                stopsig = WSTOPSIG(wstatus);

                i_have_the_conch_dont_interrupt_me[0] = 'I';
                i_have_the_conch_dont_interrupt_me[1] = ' ';
                i_have_the_conch_dont_interrupt_me[2] = 'H';
                i_have_the_conch_dont_interrupt_me[3] = 'A';
                i_have_the_conch_dont_interrupt_me[4] = 'V';
                i_have_the_conch_dont_interrupt_me[5] = 'E';
                i_have_the_conch_dont_interrupt_me[6] = ' ';
                i_have_the_conch_dont_interrupt_me[7] = 'T';
                i_have_the_conch_dont_interrupt_me[8] = 'H';
                i_have_the_conch_dont_interrupt_me[9] = 'E';
                i_have_the_conch_dont_interrupt_me[10] = ' ';
                i_have_the_conch_dont_interrupt_me[11] = 'C';
                i_have_the_conch_dont_interrupt_me[12] = 'O';
                i_have_the_conch_dont_interrupt_me[13] = 'N';
                i_have_the_conch_dont_interrupt_me[14] = 'C';
                i_have_the_conch_dont_interrupt_me[15] = 'H';
                i_have_the_conch_dont_interrupt_me[16] = ' ';
                i_have_the_conch_dont_interrupt_me[17] = 'D';
                i_have_the_conch_dont_interrupt_me[18] = 'O';
                i_have_the_conch_dont_interrupt_me[19] = 'N';
                i_have_the_conch_dont_interrupt_me[20] = '\x05';
                i_have_the_conch_dont_interrupt_me[21] = 'T';
                i_have_the_conch_dont_interrupt_me[22] = ' ';
                i_have_the_conch_dont_interrupt_me[23] = 'I';
                i_have_the_conch_dont_interrupt_me[24] = 'N';
                i_have_the_conch_dont_interrupt_me[25] = 'T';
                i_have_the_conch_dont_interrupt_me[26] = 'E';
                i_have_the_conch_dont_interrupt_me[27] = 'R';
                i_have_the_conch_dont_interrupt_me[28] = 'R';
                i_have_the_conch_dont_interrupt_me[29] = 'U';
                i_have_the_conch_dont_interrupt_me[30] = 'P';
                i_have_the_conch_dont_interrupt_me[31] = 'T';
                i_have_the_conch_dont_interrupt_me[32] = ' ';
                i_have_the_conch_dont_interrupt_me[33] = 'M';
                i_have_the_conch_dont_interrupt_me[34] = 'E';
                i_have_the_conch_dont_interrupt_me[35] = '\0';

                if (stopsig == SIGSEGV)
                {
                    /* catched SIGSEGV from second process
                       execution based on exception */
                    call_real_ptrace(PTRACE_GETREGS, current_pid, (void *)0x0, &regs);
                    return_inst_addr = call_real_ptrace(PTRACE_PEEKDATA, current_pid, (void *)regs.esp, (void *)0x0);
                    instruction = call_real_ptrace(PTRACE_PEEKDATA, current_pid, (void *)(regs.esp + 4), (void *)0x0);
                    param1 = (long *)call_real_ptrace(PTRACE_PEEKDATA, current_pid, (void *)(regs.esp + 8),
                                                        (void *)0x0);
                    param2 = call_real_ptrace(PTRACE_PEEKDATA, current_pid, (void *)(regs.esp + 0xc),
                                                (void *)0x0);
                    do
                    {
                    } while (regs.eip == -1);
                    if (instruction == INS_XOR)
                    {
                        regs.eax = (uint)param1 ^ param2;
                    }
                    else
                    {
                        if (instruction < INS_XOR + 1)
                        {
                            if (instruction == INS_COMPARE_FLAG)
                            {
                                regs.eax = param2;
                                if (param2 != 0xffffffff)
                                {
                                    read_data_from_memory(current_pid, param1, (long *)flag, 0x3e);
                                    compare_with_no_flare = strncmp(flag + 0x30, "@no-flare.com", 0xd);
                                    if (compare_with_no_flare != 0)
                                    {
                                        regs.eax = -1;
                                    }
                                }
                            }
                            else
                            {
                                if (instruction == INS_INCREMENT)
                                {
                                    regs.eax = (int)param1 + 1;
                                }
                                else
                                {
                                    if (instruction == INS_DECRYPT_STRING_BYTE)
                                    {
                                        regs.eax = param2 - 1 & 0xf | ((int)param1 + -1) * 0x10;
                                    }
                                }
                            }
                        }
                        else
                        {
                            if (instruction == INS_ADD)
                            {
                                regs.eax = param2 + (int)param1;
                            }
                            else
                            {
                                if (instruction == INS_SET_TEA_KEY_SCHEDULE_CONSTANT)
                                {
                                    regs.eax = -0x61c88647;
                                }
                                else
                                {
                                    if (instruction == INS_ROR)
                                    {
                                        regs.eax = ror((long)param1, param2);
                                    }
                                }
                            }
                        }
                    }
                    regs.eip = return_inst_addr;
                    regs.esp = regs.esp + 4;
                    call_real_ptrace(PTRACE_SETREGS, current_pid, (void *)0x0, &regs);
                    call_real_ptrace(PTRACE_CONT, current_pid, (void *)0x0, (void *)0x0);
                }
                else
                {
                    if (stopsig < (void *)(SIGSEGV + 0x1))
                    {
                        if (stopsig == (void *)SIGINT)
                        {
                            // Interruption, fuck off
                            puts(i_have_the_conch_dont_interrupt_me);
                            call_real_ptrace(PTRACE_CONT, current_pid, (void *)0x0, (void *)0x0);
                        }
                        else
                        {
                        _continue_execution:
                            /* Continue with signal == 0 */
                            call_real_ptrace(PTRACE_CONT, current_pid, (void *)0x0, (void *)0x0);
                        }
                    }
                    else
                    {
                        if (stopsig == (void *)SIGALRM)
                        {
                            /* Write one in kill_send */
                            call_real_ptrace(PTRACE_POKEDATA, current_pid, &kill_send, (void *)0x1);
                            call_real_ptrace(PTRACE_CONT, current_pid, (void *)0x0, stopsig);
                            return;
                        }
                        if (stopsig != (void *)SIGSTOP)
                            goto _continue_execution;
                        call_real_ptrace(PTRACE_CONT, current_pid, (void *)0x0, (void *)0x13);
                    }
                }
            }
        } while ((wstatus & 0x7fU) != 0);
    }
    return;
}
```