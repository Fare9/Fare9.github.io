---
title: "Analysis of Virtual.1 by Bagolymadar"
excerpt: "The following post will describe the analysis of Virtual.1 a crakcme that implements a simple virtual machine, I used Triton emulation capabilities to solve it. Here I show an analysis of the VM, and the resources I used to do it."
categories:
    - Reverse Engineering
    - Code Virtualization
tags:
    - RE
    - Binary Analysis
last_modified_at: 2026-04-05T20:00:00
toc: true
---

In the following post will describe the analysis of Virtual.1 a crakcme that implements a simple virtual machine, I used Triton emulation capabilities to solve it. Here I show an analysis of the VM, and the resources I used to do it.

You can find all the resources here: [Virtual.1](https://github.com/Fare9/My-Symbolic-Execution/tree/master/virtual.1).

## Authors

Writer:

* Eduardo Blazquez

# Virtual.1 by Bagolymadar

Welcome my friend, today we are going to do an analysis of an old VM crackme I discovered on crackmes.one — `bagolymadar's virtual.1 (Linux)`, available at: https://crackmes.one/crackme/5f3a64df33c5d42a7c667d45

I was a bit bored and looked for a simple VM crackme. The idea of the crackme is to write a keygen, and to do that, two things are mandatory:

* Analyze the VM to understand how it works.
* Understand the code run by the VM in order to know the real executed logic.

<figure style="text-align: center;">
    <a href="/assets/images/dungeons_and_dragons.jpg">
        <img src="/assets/images/dungeons_and_dragons.jpg">
    </a>
</figure>

## Code Virtualization

Code Virtualization is a protection technique where the program implements its own small CPU. Together with this CPU, the protection also contains a structure that represents things like registers, a stack, and memory. The difficulty here is not only understanding the x86 code that we can see in a disassembler — we also need to understand how this virtual CPU works, and then separately understand the code that runs inside it.

A good analogy: imagine you find a document written in a made-up language. Before you can understand what the document says, you first need to learn the rules of that language. The VM is the language, and the bytecode is the document.

There are commercial protections with virtualization capabilities (like VMProtect or Themida), but in this crackme the protection is implemented directly in the binary, and the bytecode was likely produced with a small custom assembler written by the author.

## The Crackme

The crackme is a 64-bit ELF binary, not stripped, so we can access the symbols. The virtualized bytecode is not easy to read directly, and neither is the virtual CPU that executes it. We can check it out with `file`:

```console
$ file virtual.1
virtual.1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3e7ac84584b944be377a3a42335f38dd1c85ee95, for GNU/Linux 3.2.0, not stripped
```

If we run the binary we get:

```bash
$ ./virtual.1 


                                                                     __     ___ ____ _____ _   _   _    _       _ 
                                                                     \ \   / (_)  _ \_   _| | | | / \  | |     / |
                                                                      \ \ / /| | |_) || | | | | |/ _ \ | |     | |
                                                                       \ V / | |  _ < | | | |_| / ___ \| |___ _| |
                                                                        \_/  |_|_| \_\|_|  \___/_/   \_\_____(_)_|
                                                                                                                  bagolymadar
                                                                                                                    2020.08



Username:
```

If we try whatever when the program asks for a username and a serial:

```bash
Username: Pepe
Serial: ABCD1234567890

    Nope, this is incorrect!
```

The username and the serial are not correct, so we need to dig deeper.

### Analysis of the Binary

I will use Binary Ninja for this challenge, but you can use any disassembler/decompiler you like. If we open the binary, it finds the `main` function right away. The High Level IL view gives us something close to C source code:

```c
00401130    int32_t main(int32_t argc, char** argv, char** envp)
0040113c        printmenu()
00401154        printf(format: "%s", "Username: ")
00401170        char name_buffer[0x100]
00401170        
00401170        if (fgets(&name_buffer, n: 0xfa, fp: __TMC_END__) == 0)
00401212            puts(str: "\n    Nope, this is incorrect!\n")
00401170        else
00401176            char i = name_buffer[0]
0040117a            char (* rdx_1)[0x100] = &name_buffer
0040117f            if (i != 0)
00401192                do
00401196                    if (i == 0xa)
00401198                        *rdx_1 = 0
00401198                        break
00401188                    i = (*rdx_1)[1]
0040118c                    rdx_1 = &(*rdx_1)[1]
00401192                while (i != 0)
00401192            
004011ab            printf(format: "%s", "Serial: ")
004011cf            char serial_value[0x108]
004011cf            
004011cf            if (fgets(buf: &serial_value, n: 0xfa, fp: __TMC_END__) == 0)
00401212                puts(str: "\n    Nope, this is incorrect!\n")
004011cf            else
004011d1                char i_1 = serial_value[0]
004011db                if (i_1 != 0)
004011dd                    char (* rdx_3)[0x108] = &serial_value
004011f2                    do
004011f6                        if (i_1 == 0xa)
004011f8                            *rdx_3 = 0
004011f8                            break
004011e8                        i_1 = (*rdx_3)[1]
004011ec                        rdx_3 = &(*rdx_3)[1]
004011f2                    while (i_1 != 0)
004011f2                
00401209                if (vmstart(name: &name_buffer, serial: &serial_value) == 1)
0040122b                    puts(str: "\n    Yep, you got it!\n")
00401209                else
00401212                    puts(str: "\n    Nope, this is incorrect!\n")
00401223        return 0
```

The structure is simple — `fgets` reads both the username and the serial, a small loop strips the trailing newline, and then everything is handed off to `vmstart`. If `vmstart` returns 1 we win, otherwise we lose. The goal of the crackme is not to patch the binary but to understand the validation well enough to generate a correct serial for any username.

If we look at `vmstart`:

```c
004017f0    int64_t vmstart(char* name, char* serial)
00401803        __builtin_memset(dest: &vm_data, ch: 0, count: 0xc0)
00401810        vm_data.NAME = name
00401814        vm_data.SERIAL = serial
0040181f        vm_data.SP = &__TMC_END__
00401826        virtualcpu(vm: &vm_data)
0040182f        return vm_data.result
```

A block of memory (`vm_data`) is zeroed out, the name and serial pointers are stored inside it, and then the whole structure is passed to `virtualcpu`. Whatever `virtualcpu` leaves in `vm_data.result` becomes the return value. So the real question is — what does `virtualcpu` do?

### How a Virtual Machine Works

Before entering `virtualcpu`, it helps to understand the general model. A code virtualization protection tries to emulate a real CPU by providing:

- **Registers** — locations to store temporary values, implemented as fields in a struct or slots in an array.
- **A program counter (PC)** — a register that holds the address of the next instruction to execute, equivalent to `RIP` in x86-64.
- **A stack pointer (SP)** — a register that points to the top of the stack, equivalent to `RSP` in x86-64.
- **Flags** — bits that record the result of comparisons, like the zero flag and the less-than flag.
- **A dispatcher** — a big `switch` statement that reads the next opcode from the bytecode stream and runs the corresponding handler.

The bytecode is just an array of bytes in memory. The dispatcher reads one byte (the opcode), optionally reads one or two more bytes (the operands), executes the operation, advances the PC, and loops back. This is exactly the fetch-decode-execute cycle of a real CPU, just implemented in software.

In this crackme the VM struct looks like this once we rename the fields:

| Offset | Field | Description |
|--------|-------|-------------|
| `+0x00` | `ACC` | Accumulator register (r0) |
| `+0x08` | `r1` | General purpose register |
| `+0x10` | `result` | Result register (r2), returned by vmstart |
| `+0x18` | `PC` | Program counter |
| `+0x20` | `NAME` | Pointer to the name buffer |
| `+0x28` | `SERIAL` | Pointer to the serial buffer |
| `+0x30` | `FLAGS` | Condition flags (bit0 = zero/equal, bit1 = less-than) |
| `+0x38` | `SP` | Stack pointer |

Each field is 8 bytes wide, so register index `N` maps to `vm + (N * 8)`. That is why every handler in the switch does `vm + (zx.q(op.b) << 3)` — it is just an index multiplied by 8.

Do you want to know what happens next? Keep reading!

<figure style="text-align: center;">
    <a href="/assets/images/backtothefuture.gif">
        <img src="/assets/images/backtothefuture.gif">
    </a>
</figure>

### Analysis of the Binary — Part 2: Understanding the VM Handlers

Now let's enter `virtualcpu`. The outer loop and dispatch look like this:

```c
00401830    uint64_t virtualcpu(struct vm_struct* vm)
00401837        uint64_t op
00401837        
00401837        while (true)
00401837            char* p_instr = &bytecode + vm->PC
0040183b            op.b = *p_instr
0040183b            int16_t* p_operands = &p_instr[1]
0040183e            int64_t rcx
0040183e            
0040183e            switch (op.b)
```

At each iteration, the current instruction is fetched from `bytecode + PC`. The first byte is the opcode, and `p_operands` points to the bytes that follow. Let's go through some handlers to build intuition.

**MOVQ** — copies a full 64-bit register value into another register. Both operands are register indices:

```c
case MOVQ  // opcode 0x01
    op.b = *p_operands             // destination register index
    uint64_t* dst = vm + (zx.q(op.b) << 3)
    op.b = *(p_operands + 1)       // source register index
    *dst = *(vm + (zx.q(op.b) << 3))
    vm->PC += 3
```

**MOVB** — same idea but copies only the low byte, leaving the upper 7 bytes of the destination untouched:

```c
case MOVB  // opcode 0x02
    op.b = *p_operands
    char* dst = vm + (zx.q(op.b) << 3)
    op.b = *(p_operands + 1)
    op.b = *(vm + (zx.q(op.b) << 3))   // read low byte of source
    *dst = op.b                          // write low byte of destination
    vm->PC += 3
```

**JMP** — unconditional jump. Reads a 16-bit big-endian address from the operands and sets `PC` directly:

```c
case JMP  // opcode 0x11
    // read 16-bit big-endian address
    op.w = *p_operands
    char temp = op.b
    op.b = op:1.b
    op:1.b = temp
    vm->PC = zx.q(op.w)
```

The byte swap is there because the bytecode stores addresses in big-endian order but x86 is little-endian. This pattern — read word, swap bytes, assign to PC — appears in every instruction that encodes an address.

**PUSH_IMM8** — pushes an immediate byte onto the VM stack. The stack grows downward, just like on a real CPU:

```c
case PUSH_IMM8  // opcode 0x09
    vm->SP -= 1
    op.b = *p_operands
    *vm->SP = op.b
    vm->PC += 2
```

**INC / DEC** — increment or decrement a register by 1. The register index is the single operand:

```c
case INC  // opcode 0x41
    op.b = *p_operands
    int64_t* reg = vm + (zx.q(op.b) << 3)
    *reg += 1
    vm->PC += 2

case DEC  // opcode 0x14
    op.b = *p_operands
    int64_t* reg = vm + (zx.q(op.b) << 3)
    *reg -= 1
    vm->PC += 2
```

**PTR_NULL** — dereferences a register as a pointer, reads a byte from that address, and sets FLAGS bit0 to 1 if the byte is zero. This is used to check for string termination:

```c
case PTR_NULL  // opcode 0x1e
    op.b = *p_operands
    op.b = **(vm + (zx.q(op.b) << 3))   // dereference pointer in register
    op.b = op.b == 0
    vm->FLAGS = (vm->FLAGS & ~1) | op.b
    vm->PC += 2
```

**CMPZ** — similar to PTR_NULL but tests the register value itself rather than what it points to:

```c
case CMPZ  // opcode 0x54
    op.b = *p_operands
    op.b = *(vm + (zx.q(op.b) << 3)) == 0
    vm->FLAGS = (vm->FLAGS & ~1) | op.b
    vm->PC += 2
```

**LOAD_SERIAL / LOAD_NAME** — read the next byte from the serial or name buffer into `ACC`, then advance the pointer. These are single-byte instructions with no operands:

```c
case LOAD_SERIAL  // opcode 0x52
    vm->ACC = zx.q(*vm->SERIAL)
    vm->SERIAL += 1
    vm->PC += 1

case LOAD_NAME  // opcode 0x69
    vm->ACC = zx.q(*vm->NAME)
    vm->NAME += 1
    vm->PC += 1
```

**CMP_IMM8** — compares a register against an immediate byte and writes the result into two bits of FLAGS. Bit 0 is the equal flag, bit 1 is the less-than flag:

```c
case CMP_IMM8  // opcode 0x7f
    int64_t* reg = vm + (zx.q(*p_operands) << 3)
    uint8_t imm = *(p_operands + 1)
    int64_t val = *reg
    bool lt = val s< imm
    op.b = (val == imm)
    op.b |= (lt << 1)
    vm->FLAGS = (vm->FLAGS & ~3) | op.b
    vm->PC += 3
```

**JZ / JNZ / JL** — conditional jumps that read FLAGS and either take the big-endian address from the operands or fall through by incrementing PC by 3:

```c
case JZ  // opcode 0x55 -- jump if FLAGS bit0 == 1 (equal/zero)
    if ((vm->FLAGS & 1) == 0)
        vm->PC += 3
    else
        // big-endian address -> PC

case JNZ  // opcode 0x81 -- jump if FLAGS bit0 == 0 (not equal)
    if ((vm->FLAGS & 1) != 0)
        vm->PC += 3
    else
        // big-endian address -> PC

case JL  // opcode 0x95 -- jump if FLAGS bit1 == 1 (less-than)
    if ((vm->FLAGS & 2) == 0)
        vm->PC += 3
    else
        // big-endian address -> PC
```

**CALL / RET** — subroutine call and return. `CALL` pushes the return address (PC + 3) as a 16-bit value onto the stack and jumps. `RET` pops it and jumps back:

```c
case CALL  // opcode 0xab
    vm->SP -= 2
    *vm->SP = (vm->PC + 3).w   // return address stored as 16-bit value
    // big-endian address -> PC

case RET  // opcode 0xba
    op = zx.q(*vm->SP)
    vm->SP += 2
    vm->PC = op
```

**HLT** — terminates the VM loop and returns. The result of the validation is whatever is left in `vm->result`, which the bytecode sets explicitly before calling HLT:

```c
default
    if (op.b == HLT)  // opcode 0x4c
        return op
```

The remaining handlers follow the same pattern. Here is the complete opcode table:

| Opcode | Mnemonic | Description |
|--------|----------|-------------|
| `0x01` | `MOVQ r_dst, r_src` | 64-bit register-to-register copy |
| `0x02` | `MOVB r_dst, r_src` | 8-bit register-to-register copy (low byte only) |
| `0x09` | `PUSH_IMM8 imm8` | Push immediate byte onto stack |
| `0x11` | `JMP imm16` | Unconditional jump (big-endian address) |
| `0x14` | `DEC r` | Decrement register by 1 |
| `0x1e` | `PTR_NULL r` | Test if `*reg == 0`, write result to FLAGS bit0 |
| `0x41` | `INC r` | Increment register by 1 |
| `0x4c` | `HLT` | Halt and return |
| `0x52` | `LOAD_SERIAL` | Load byte from `*SERIAL` into ACC, advance pointer |
| `0x54` | `CMPZ r` | Test if `reg == 0`, write result to FLAGS bit0 |
| `0x55` | `JZ imm16` | Jump if FLAGS bit0 == 1 (equal/zero) |
| `0x56` | `MOV_IMM8 r, imm8` | Load immediate byte into register (zero-extended) |
| `0x69` | `LOAD_NAME` | Load byte from `*NAME` into ACC, advance pointer |
| `0x7f` | `CMP_IMM8 r, imm8` | Compare register vs immediate, set FLAGS bit0/bit1 |
| `0x81` | `JNZ imm16` | Jump if FLAGS bit0 == 0 (not equal) |
| `0x8d` | `PUSH_REG r` | Push full 64-bit register onto stack |
| `0x8e` | `POP_REG r` | Pop full 64-bit value from stack into register |
| `0x8f` | `SHR r, imm8` | Logical shift right |
| `0x90` | `TEST_IMM8 r, imm8` | AND register with immediate, set FLAGS bit0 if zero |
| `0x93` | `ADD_REG r_dst, r_src` | Add register to register |
| `0x94` | `AND_IMM64 r, imm64` | AND register with 8-byte immediate |
| `0x95` | `JL imm16` | Jump if FLAGS bit1 == 1 (less-than) |
| `0x96` | `SUB_IMM8 r, imm8` | Subtract immediate byte from register |
| `0x97` | `SHL r, imm8` | Logical shift left |
| `0x98` | `CMP_REG r_dst, r_src` | Compare two registers, set FLAGS bit0/bit1 |
| `0x99` | `MOV_IMM64 r, imm64` | Load 8-byte immediate into register |
| `0x9a` | `ROL r_dst, r_src` | Rotate left by register value |
| `0x9b` | `NOT r` | Bitwise NOT of low byte |
| `0x9c` | `XOR r_dst, r_src` | XOR register with register (byte) |
| `0xab` | `CALL imm16` | Push return address, jump |
| `0xba` | `RET` | Pop 16-bit address, jump |

And the full `virtualcpu` function with all symbols renamed:

```c
00401830    uint64_t virtualcpu(struct vm_struct* vm)

00401837        uint64_t op
00401837        
00401837        while (true)
00401837            char* p_instr = &bytecode + vm->PC
0040183b            op.b = *p_instr
0040183b            int16_t* p_operands = &p_instr[1]
0040183e            int64_t rcx
0040183e            
0040183e            switch (op.b)
0040183c                case MOVQ  // MOV  dst_reg, src_reg
00401939                    op.b = *p_operands  // get first operand
00401942                    uint64_t* dst = vm + (zx.q(op.b) << 3)
00401946                    op.b = *(p_operands + 1)  // get second operand
00401956                    *dst = *(vm + (zx.q(op.b) << 3))
00401959                    vm->PC += 3
00401844                case MOVB  // MOVB  dst_reg, src_reg
00401963                    op.b = *p_operands
0040196c                    char* r8_1 = vm + (zx.q(op.b) << 3)
00401970                    op.b = *(p_operands + 1)
0040197d                    op.b = *(vm + (zx.q(op.b) << 3))
00401980                    *r8_1 = op.b
00401983                    vm->PC += 3
0040184c                case PUSH_IMM8  // PUSH  imm8
00401991                    vm->SP -= 1
00401997                    op.b = *p_operands
00401998                    *vm->SP = op.b
0040199b                    vm->PC += 2
00401854                case JMP
004019a5                    op.w = *p_operands
004019a7                    char temp0_1 = op.b
004019a7                    op.b = op:1.b
004019a7                    op:1.b = temp0_1
004019ad                    vm->PC = zx.q(op.w)
0040185c                case DEC
004019b6                    op.b = *p_operands
004019bf                    int64_t* r8_4 = vm + (zx.q(op.b) << 3)
004019c3                    *r8_4 -= 1
004019c6                    vm->PC += 2
00401864                case PTR_NULL
004019d0                    op.b = *p_operands
004019e0                    op.b = **(vm + (zx.q(op.b) << 3))
004019e8                    op.b = op.b == 0
004019f2                    rcx.b = (vm->FLAGS & 0xfffffffffffffffe).b | op.b
004019f4                    vm->FLAGS = rcx
004019f7                    vm->PC += 2
0040186c                case INC
00401a01                    op.b = *p_operands
00401a0a                    int64_t* r8_7 = vm + (zx.q(op.b) << 3)
00401a0e                    *r8_7 += 1
00401a11                    vm->PC += 2
0040183e                default
00401876                    if (op.b == HLT)
00401a1c                        return op
00401a1c                    
0040187e                    void* r10
0040187e                    
0040187e                    switch (op.b)
0040187c                        case LOAD_SERIAL
00401a2e                            vm->ACC = zx.q(*vm->SERIAL)
00401a31                            vm->SERIAL = &vm->SERIAL[1]
00401a34                            vm->PC += 1
00401884                        case CMPZ
00401a3e                            op.b = *p_operands
00401a55                            op.b = *(vm + (zx.q(op.b) << 3)) == 0
00401a5f                            rcx.b = (vm->FLAGS & 0xfffffffffffffffe).b | op.b
00401a61                            vm->FLAGS = rcx
00401a64                            vm->PC += 2
0040188c                        case JZ
00401a79                            if ((vm->FLAGS & 1) == 0)
00401a8c                                vm->PC += 3
00401a79                            else
00401a7b                                op.w = *p_operands
00401a7d                                char temp0_2 = op.b
00401a7d                                op.b = op:1.b
00401a7d                                op:1.b = temp0_2
00401a83                                vm->PC = zx.q(op.w)
00401894                        case MOV_IMM8
00401a96                            op.b = *p_operands
00401aa3                            uint64_t rax_5
00401aa3                            rax_5.b = *(p_operands + 1)
00401aa8                            *(vm + (zx.q(op.b) << 3)) = zx.q(rax_5.b)
00401aab                            vm->PC += 3
0040189c                        case LOAD_NAME
00401ac6                            vm->ACC = zx.q(*vm->NAME)
00401ac9                            vm->NAME = &vm->NAME[1]
00401acc                            vm->PC += 1
004018a4                        case CMP_IMM8
00401ad6                            op.b = *p_operands
00401adf                            int64_t* r1 = vm + (zx.q(op.b) << 3)
00401ae3                            uint64_t rax_7
00401ae3                            rax_7.b = *(p_operands + 1)
00401ae4                            op = zx.q(rax_7.b)
00401ae8                            int64_t r1_content = *r1
00401ae8                            bool cond:2_1 = r1_content s< op
00401aeb                            op.b = r1_content == op
00401aee                            r10.b = cond:2_1
00401af2                            r10.b <<= 1
00401af5                            op.b |= r10.b
00401b03                            rcx.b = (vm->FLAGS & 0xfffffffffffffffc).b | op.b
00401b05                            vm->FLAGS = rcx
00401b08                            vm->PC += 3
004018ac                        case JNZ
00401b1d                            if ((vm->FLAGS & 1) != 0)
00401b30                                vm->PC += 3
00401b1d                            else
00401b1f                                op.w = *p_operands
00401b21                                char temp0_3 = op.b
00401b21                                op.b = op:1.b
00401b21                                op:1.b = temp0_3
00401b27                                vm->PC = zx.q(op.w)
004018b4                        case PUSH_REG
00401b3e                            vm->SP -= 8
00401b45                            op.b = *p_operands
00401b55                            *vm->SP = *(vm + (zx.q(op.b) << 3))
00401b58                            vm->PC += 2
004018bc                        case POP_REG
00401b62                            op.b = *p_operands
00401b73                            int64_t SP = vm->SP
00401b76                            vm->SP += 8
00401b7d                            *(vm + (zx.q(op.b) << 3)) = *SP
00401b80                            vm->PC += 2
004018c4                        case SHR
00401b8a                            op.b = *p_operands
00401b93                            uint64_t* reg = vm + (zx.q(op.b) << 3)
00401b97                            op.b = *(p_operands + 1)
00401b98                            rcx.b = op.b
00401b9a                            *reg u>>= rcx.b
00401b9d                            vm->PC += 3
004018cc                        case TEST_IMM8
00401ba7                            op.b = *p_operands
00401bb0                            int64_t* r9_8 = vm + (zx.q(op.b) << 3)
00401bb4                            op.b = *(p_operands + 1)
00401bbc                            op.b = (*r9_8 & zx.q(op.b)) == 0
00401bca                            r10.b = (vm->FLAGS & 0xfffffffffffffffe).b | op.b
00401bcd                            vm->FLAGS = r10
00401bd0                            vm->PC += 3
004018d4                        case ADD_REG
00401bda                            op.b = *p_operands
00401be3                            uint64_t* reg1 = vm + (zx.q(op.b) << 3)
00401be7                            op.b = *(p_operands + 1)
00401bfa                            *reg1 += *(vm + (zx.q(op.b) << 3))
00401bfd                            vm->PC += 3
004018dc                        case AND_IMM64
00401c07                            op.b = *p_operands
00401c07                            char* rsi_25 = p_operands + 1
00401c10                            void** r9_10 = vm + (zx.q(op.b) << 3)
00401c14                            op.b = *rsi_25
00401c14                            char* rsi_26 = &rsi_25[1]
00401c19                            uint64_t rax_9
00401c19                            rax_9.b = *rsi_26
00401c19                            char* rsi_27 = &rsi_26[1]
00401c1e                            uint64_t rax_10
00401c1e                            rax_10.b = *rsi_27
00401c1e                            char* rsi_28 = &rsi_27[1]
00401c23                            uint64_t rax_11
00401c23                            rax_11.b = *rsi_28
00401c23                            char* rsi_29 = &rsi_28[1]
00401c28                            uint64_t rax_12
00401c28                            rax_12.b = *rsi_29
00401c28                            char* rsi_30 = &rsi_29[1]
00401c2d                            uint64_t rax_13
00401c2d                            rax_13.b = *rsi_30
00401c2d                            char* rsi_31 = &rsi_30[1]
00401c32                            uint64_t rax_14
00401c32                            rax_14.b = *rsi_31
00401c37                            op.b = rsi_31[1]
00401c3e                            *r9_10 &= op
00401c41                            vm->PC += 0xa
004018e4                        case JL
00401c56                            if ((vm->FLAGS & 2) == 0)
00401c69                                vm->PC += 3
00401c56                            else
00401c58                                op.w = *p_operands
00401c5a                                char temp0_4 = op.b
00401c5a                                op.b = op:1.b
00401c5a                                op:1.b = temp0_4
00401c60                                vm->PC = zx.q(op.w)
004018ec                        case SUB_IMM8
00401c73                            op.b = *p_operands
00401c7c                            char* r9_11 = vm + (zx.q(op.b) << 3)
00401c80                            op.b = *(p_operands + 1)
00401c81                            *r9_11 -= op.b
00401c84                            vm->PC += 3
004018f4                        case SHL
00401c8e                            op.b = *p_operands
00401c97                            int64_t* r9_12 = vm + (zx.q(op.b) << 3)
00401c9b                            op.b = *(p_operands + 1)
00401c9c                            rcx.b = op.b
00401c9e                            *r9_12 <<= rcx.b
00401ca1                            vm->PC += 3
004018fc                        case CMP_REG
00401cab                            op.b = *p_operands
00401cb4                            int64_t* r8_25 = vm + (zx.q(op.b) << 3)
00401cb8                            uint64_t rax_16
00401cb8                            rax_16.b = *(p_operands + 1)
00401cc5                            op = *(vm + (zx.q(rax_16.b) << 3))
00401cc8                            int64_t temp2_1 = *r8_25
00401cc8                            bool cond:3_1 = temp2_1 s< op
00401ccb                            op.b = temp2_1 == op
00401cce                            r10.b = cond:3_1
00401cd2                            r10.b <<= 1
00401cd5                            op.b |= r10.b
00401ce3                            rcx.b = (vm->FLAGS & 0xfffffffffffffffc).b | op.b
00401ce5                            vm->FLAGS = rcx
00401ce8                            vm->PC += 3
00401904                        case MOV_IMM64
00401cf2                            op.b = *p_operands
00401cf2                            char* rsi_41 = p_operands + 1
00401cfb                            uint64_t* r8_27 = vm + (zx.q(op.b) << 3)
00401cff                            uint64_t rax_20
00401cff                            rax_20.b = *rsi_41
00401cff                            char* rsi_42 = &rsi_41[1]
00401d04                            uint64_t rax_21
00401d04                            rax_21.b = *rsi_42
00401d04                            char* rsi_43 = &rsi_42[1]
00401d09                            uint64_t rax_22
00401d09                            rax_22.b = *rsi_43
00401d09                            char* rsi_44 = &rsi_43[1]
00401d0e                            uint64_t rax_23
00401d0e                            rax_23.b = *rsi_44
00401d0e                            char* rsi_45 = &rsi_44[1]
00401d13                            uint64_t rax_24
00401d13                            rax_24.b = *rsi_45
00401d13                            char* rsi_46 = &rsi_45[1]
00401d18                            uint64_t rax_25
00401d18                            rax_25.b = *rsi_46
00401d18                            char* rsi_47 = &rsi_46[1]
00401d1d                            uint64_t rax_26
00401d1d                            rax_26.b = *rsi_47
00401d22                            op.b = rsi_47[1]
00401d23                            *r8_27 = op
00401d26                            vm->PC += 0xa
0040190c                        case ROL
00401d30                            op.b = *p_operands
00401d39                            int64_t* r8_28 = vm + (zx.q(op.b) << 3)
00401d3d                            uint64_t rax_28
00401d3d                            rax_28.b = *(p_operands + 1)
00401d4a                            rcx.b = *(vm + (zx.q(rax_28.b) << 3))
00401d4d                            *r8_28 = rol.q(*r8_28, rcx.b)
00401d50                            vm->PC += 3
00401914                        case NOT
00401d5a                            op.b = *p_operands
00401d63                            char* r8_29 = vm + (zx.q(op.b) << 3)
00401d67                            *r8_29 = not.b(*r8_29)
00401d6a                            vm->PC += 2
0040191c                        case XOR
00401d74                            op.b = *p_operands
00401d7d                            char* r8_30 = vm + (zx.q(op.b) << 3)
00401d81                            uint64_t rax_32
00401d81                            rax_32.b = *(p_operands + 1)
00401d8e                            op.b = *(vm + (zx.q(rax_32.b) << 3))
00401d91                            *r8_30 ^= op.b
00401d94                            vm->PC += 3
00401924                        case CALL
00401da2                            vm->SP -= 2
00401daa                            op.w = vm->PC.w
00401dae                            op.w += 3
00401db5                            *vm->SP = op.w
00401db9                            op.w = *p_operands
00401dbb                            char temp0_5 = op.b
00401dbb                            op.b = op:1.b
00401dbb                            op:1.b = temp0_5
00401dc1                            vm->PC = zx.q(op.w)
0040187e                        default
0040192e                            if (op.b != RET)
0040192e                                break
0040192e                            
00401dd0                            op = zx.q(*vm->SP)
00401dd4                            vm->SP += 2
00401ddc                            vm->PC = op
00401ddc        
00401de4        vm->result = 0
00401dec        return op
```

At this point we have a complete picture of the virtual CPU. We know what every instruction does, we know how the registers and flags are laid out, and we know where the bytecode lives in memory. The next step is to actually trace the execution and read the bytecode logic — and for that we will use Triton as a concrete emulator, building a VM-level disassembler on top of it.

#### Triton, your favorite emulator

As I mentioned, we cannot simply symbolize the input data, run the VM code until the data has been transformed into a final value, and then use Z3 to solve for what we need. The problem here is different — the VM does not compute a single expression from the serial and compare it against a constant. Instead, it reads the serial byte by byte and uses those values to drive control flow. A wrong serial byte does not just produce the wrong hash value — it makes the VM jump to the failure path immediately. Symbolic execution would be useful if all paths eventually converged at a single comparison, but here incorrect input causes the VM to terminate early, which means Z3 never sees a constraint worth solving.

So symbolic execution is off the table for this one. What we can do instead is use Triton purely as a concrete x86-64 emulator — no symbolization, no Z3 — and instrument it to print the VM instructions as they execute. That gives us a clean VM-level trace that we can read manually, which is exactly what we need to understand the algorithm.

Let's start building the emulator (`solve-vm.py`). First, the configuration variables — binary path, base address, the VM struct address, and the offsets of each field inside it:

```python
BINARY_PATH      = "./virtual.1"
BASE_ADDRESS     = 0x400000

# VM struct base
VM_STRUCT        = 0x404230

# VM struct offsets
VM_ACC           = VM_STRUCT + 0x00   # r0 / accumulator
VM_R1            = VM_STRUCT + 0x08   # r1
VM_RESULT        = VM_STRUCT + 0x10   # r2 / result / return value
VM_PC            = VM_STRUCT + 0x18   # r3 / program counter
VM_NAME          = VM_STRUCT + 0x20   # r4 / pointer to name buffer
VM_SERIAL        = VM_STRUCT + 0x28   # r5 / pointer to serial buffer
VM_FLAGS         = VM_STRUCT + 0x30   # r6 / flags
VM_SP            = VM_STRUCT + 0x38   # r7 / stack pointer
```

Next, the bytecode base address. This is computed from the `lea rsi, [rip + 0x28d1]` instruction at `0x401830` — `rip` at execution time is `0x401837` (the next instruction), so the base is `0x401837 + 0x28d1 = 0x404108`. We also define where the emulation starts and ends:

```python
# Bytecode base: lea rsi, [rip + 0x28d1] at 0x401830, rip = 0x401837
BYTECODE_BASE    = 0x401837 + 0x28d1

# Emulation range
ADDR_VMSTART     = 0x4017f1
ADDR_VMSTART_RET = 0x40182f
```

The key insight for the VM-level disassembler is that instead of checking whether `RIP` is at the top of the dispatch loop, we check whether it has just entered a specific handler. Each opcode maps to exactly one handler address — the target of the `je` in the switch. We build a reverse map so the emulation loop can look up the opcode from the current `RIP`:

```python
# Map opcode -> x86 handler address (je targets from the switch)
OPCODE_HANDLERS = {
    0x01: 0x401939,   # MOVQ
    0x02: 0x401963,   # MOVB
    0x09: 0x40198d,   # PUSH_IMM8
    0x11: 0x4019a5,   # JMP
    0x14: 0x4019b6,   # DEC
    0x1e: 0x4019d0,   # PTR_NULL
    0x41: 0x401a01,   # INC
    0x4c: 0x401a1b,   # HLT
    0x52: 0x401a1d,   # LOAD_SERIAL
    0x54: 0x401a3e,   # CMPZ
    0x55: 0x401a6e,   # JZ
    0x56: 0x401a96,   # MOV_IMM8
    0x69: 0x401ab5,   # LOAD_NAME
    0x7f: 0x401ad6,   # CMP_IMM8
    0x81: 0x401b12,   # JNZ
    0x8d: 0x401b3a,   # PUSH_REG
    0x8e: 0x401b62,   # POP_REG
    0x8f: 0x401b8a,   # SHR
    0x90: 0x401ba7,   # TEST_IMM8
    0x93: 0x401bda,   # ADD_REG
    0x94: 0x401c07,   # AND_IMM64
    0x95: 0x401c4b,   # JL
    0x96: 0x401c73,   # SUB_IMM8
    0x97: 0x401c8e,   # SHL
    0x98: 0x401cab,   # CMP_REG
    0x99: 0x401cf2,   # MOV_IMM64
    0x9a: 0x401d30,   # ROL
    0x9b: 0x401d5a,   # NOT
    0x9c: 0x401d74,   # XOR
    0xab: 0x401d9e,   # CALL
    0xba: 0x401dc9,   # RET
}

# Reverse map: handler address -> opcode
HANDLER_TO_OPCODE = {v: k for k, v in OPCODE_HANDLERS.items()}
HANDLER_ADDRESSES = set(OPCODE_HANDLERS.values())
```

Finally, the fake buffer addresses where we place the name and serial in Triton's memory, together with a cap on the number of instructions and two command-line flags — one to print the underlying x86 instructions alongside the VM ones, and another to suppress printing inside known utility subroutines:

```python
# Fake buffers
FAKE_NAME_ADDR   = 0x00200000
FAKE_SERIAL_ADDR = 0x00300000

NAME_VALUE       = b"Pepe\x00"
SERIAL_VALUE     = b"ABCD1234\x00"

MAX_INSTRUCTIONS = 500_000

# CLI flags
PRINT_X86    = "--x86" in sys.argv
SKIP_STDLIB  = "--no-stdlib" in sys.argv
```

The `print_vm_instruction` function reads the current VM PC from memory, then reads the operand bytes from the bytecode region and formats them according to the opcode. Crucially, we read the operands before the instruction executes, while the VM state is still consistent:

```python
def print_vm_instruction(ctx, opcode):
    """Print the current VM instruction using the known opcode."""
    pc    = ctx.getConcreteMemoryValue(MemoryAccess(VM_PC,    CPUSIZE.QWORD))
    flags = ctx.getConcreteMemoryValue(MemoryAccess(VM_FLAGS, CPUSIZE.QWORD))
    acc   = ctx.getConcreteMemoryValue(MemoryAccess(VM_ACC,   CPUSIZE.QWORD))

    def bc(offset):
        return ctx.getConcreteMemoryValue(
            MemoryAccess(BYTECODE_BASE + pc + offset, CPUSIZE.BYTE))

    def bc16(offset):
        return (bc(offset) << 8) | bc(offset + 1)   # big-endian

    def bc64(offset):
        val = 0
        for i in range(8):
            val = (val << 8) | bc(offset + i)
        return val

    match opcode:
        case 0x01: s = f"MOVQ      {rname(bc(1))}, {rname(bc(2))}"
        case 0x02: s = f"MOVB      {rname(bc(1))}, {rname(bc(2))}"
        case 0x09: s = f"PUSH_IMM8 0x{bc(1):02x}"
        case 0x11: s = f"JMP       0x{bc16(1):04x}"
        case 0x14: s = f"DEC       {rname(bc(1))}"
        case 0x1e: s = f"PTR_NULL  {rname(bc(1))}"
        case 0x41: s = f"INC       {rname(bc(1))}"
        case 0x4c: s = f"HLT"
        case 0x52: s = f"LOAD_SERIAL                        ; ACC=0x{acc:02x}"
        case 0x54: s = f"CMPZ      {rname(bc(1))}"
        case 0x55: s = f"JZ        0x{bc16(1):04x}                   ; FLAGS=0x{flags:x}"
        case 0x56: s = f"MOV_IMM8  {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x69: s = f"LOAD_NAME                          ; ACC=0x{acc:02x}"
        case 0x7f: s = f"CMP_IMM8  {rname(bc(1))}, 0x{bc(2):02x}             ; FLAGS=0x{flags:x}"
        case 0x81: s = f"JNZ       0x{bc16(1):04x}                   ; FLAGS=0x{flags:x}"
        case 0x8d: s = f"PUSH_REG  {rname(bc(1))}"
        case 0x8e: s = f"POP_REG   {rname(bc(1))}"
        case 0x8f: s = f"SHR       {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x90: s = f"TEST_IMM8 {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x93: s = f"ADD_REG   {rname(bc(1))}, {rname(bc(2))}"
        case 0x94: s = f"AND_IMM64 {rname(bc(1))}, 0x{bc64(2):016x}"
        case 0x95: s = f"JL        0x{bc16(1):04x}                   ; FLAGS=0x{flags:x}"
        case 0x96: s = f"SUB_IMM8  {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x97: s = f"SHL       {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x98: s = f"CMP_REG   {rname(bc(1))}, {rname(bc(2))}             ; FLAGS=0x{flags:x}"
        case 0x99: s = f"MOV_IMM64 {rname(bc(1))}, 0x{bc64(2):016x}"
        case 0x9a: s = f"ROL       {rname(bc(1))}, {rname(bc(2))}"
        case 0x9b: s = f"NOT       {rname(bc(1))}"
        case 0x9c: s = f"XOR       {rname(bc(1))}, {rname(bc(2))}"
        case 0xab: s = f"CALL      0x{bc16(1):04x}"
        case 0xba: s = f"RET"
        case _:    s = f"UNKNOWN   0x{opcode:02x}"

    print(f"  [VM:{pc:04x}] {s}")
```

Triton does not provide a built-in way to load binaries, so we use LIEF to parse the ELF and map each loadable segment into the Triton context. We add `BASE_ADDRESS` to each segment's virtual address because the binary was compiled as a PIE — without the base offset the segments land at the wrong addresses and the opcodes decode as garbage:

```python
def load_binary(ctx: TritonContext, path: str) -> lief.Binary:
    binary = lief.parse(path)
    if binary is None:
        raise RuntimeError(f"LIEF could not parse '{path}'")

    for segment in binary.segments:
        if segment.type == lief.ELF.Segment.TYPE.LOAD:
            vaddr   = BASE_ADDRESS + segment.virtual_address
            content = bytes(segment.content)
            ctx.setConcreteMemoryAreaValue(vaddr, content)
            print(f"[LIEF] Mapped segment @ 0x{vaddr:08x}  size=0x{len(content):x}")

    return binary
```

There is also a binary patch needed. The two `movabs` instructions in `vmstart` that load the VM struct address (`0x404230`) were assembled without the PIE base, so they contain `0x4230` instead of `0x404230`. We fix them directly in Triton's memory after loading:

```python
def patch_binary(ctx: TritonContext) -> None:
    # movabs rdi, 0x404230  at 0x4017f9  (encoding: 48 BF + 8 bytes LE)
    ctx.setConcreteMemoryAreaValue(0x4017f9 + 2, (0x404230).to_bytes(8, 'little'))
    # movabs r10, 0x404230  at 0x401805  (encoding: 49 BA + 8 bytes LE)
    ctx.setConcreteMemoryAreaValue(0x401805 + 2, (0x404230).to_bytes(8, 'little'))
    print("[PATCH] Fixed VM struct address in movabs instructions")
```

The setup method places the name and serial at their fake addresses, zeroes out the VM struct, and initializes the x86 registers to match what `vmstart` would receive at its entry point:

```python
def setup_state(ctx: TritonContext) -> None:
    ctx.setConcreteMemoryAreaValue(FAKE_NAME_ADDR,   NAME_VALUE)
    ctx.setConcreteMemoryAreaValue(FAKE_SERIAL_ADDR, SERIAL_VALUE)
    ctx.setConcreteMemoryAreaValue(VM_STRUCT, b"\x00" * 0xc0)

    ctx.setConcreteRegisterValue(ctx.registers.rip, ADDR_VMSTART)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7ffff000)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7ffff000)
    ctx.setConcreteRegisterValue(ctx.registers.rdi, FAKE_NAME_ADDR)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, FAKE_SERIAL_ADDR)

    print(f"[SETUP] name         = {NAME_VALUE!r}  @ 0x{FAKE_NAME_ADDR:08x}")
    print(f"[SETUP] serial       = {SERIAL_VALUE!r}  @ 0x{FAKE_SERIAL_ADDR:08x}")
    print(f"[SETUP] BYTECODE_BASE= 0x{BYTECODE_BASE:08x}")
    print(f"[SETUP] Concrete state initialised")
```

The Triton context is initialized with x86-64 architecture and a few optimization flags that speed up concrete emulation:

```python
def init_triton() -> TritonContext:
    ctx = TritonContext(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY,    True)
    ctx.setMode(MODE.CONSTANT_FOLDING,  True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx
```

Before the emulation loop, here is `main` to show how everything fits together:

```python
def main() -> None:
    print(f"[INFO] name         = {NAME_VALUE!r}")
    print(f"[INFO] serial       = {SERIAL_VALUE!r}")
    print(f"[INFO] x86 printing = {PRINT_X86}\n")

    ctx = init_triton()
    load_binary(ctx, BINARY_PATH)
    patch_binary(ctx)
    setup_state(ctx)
    emulate(ctx)


if __name__ == "__main__":
    main()
```

The emulation loop is the standard Triton pattern — fetch the instruction bytes at `RIP`, create an `Instruction` object, call `ctx.processing()` to execute it, then move on. The only addition is the handler check: if `RIP` matches a known handler address we print the VM instruction before the x86 code executes. The `--no-stdlib` flag suppresses printing inside known utility subroutines to keep the trace focused on the high-level logic:

```python
def emulate(ctx: TritonContext) -> None:
    print(f"\n[EMU] Starting emulation from 0x{ADDR_VMSTART:08x}")
    print(f"[EMU] Printing: VM instructions {'+ x86' if PRINT_X86 else 'only'}\n")

    skip_depth = 0

    for count in range(MAX_INSTRUCTIONS):
        rip = ctx.getConcreteRegisterValue(ctx.registers.rip)

        if rip == ADDR_VMSTART_RET:
            break

        should_print_vm = False
        vm_opcode       = None

        if rip in HANDLER_ADDRESSES:
            vm_opcode = HANDLER_TO_OPCODE[rip]
            pc        = ctx.getConcreteMemoryValue(MemoryAccess(VM_PC, CPUSIZE.QWORD))

            if SKIP_STDLIB:
                if pc in SKIP_SUBROUTINES:
                    skip_depth += 1
                if vm_opcode == 0xba and skip_depth > 0:
                    skip_depth -= 1

            if skip_depth == 0:
                should_print_vm = True

        if should_print_vm:
            print_vm_instruction(ctx, vm_opcode)

        opcodes = ctx.getConcreteMemoryAreaValue(rip, 16)
        insn    = Instruction(rip, opcodes)
        ctx.processing(insn)

        if insn.getType() == OPCODE.X86.HLT:
            print(f"[EMU] HLT @ 0x{rip:08x}")
            break

        if PRINT_X86 and skip_depth == 0:
            print(f"    [x86] 0x{rip:08x}  {insn.getDisassembly()}")

    else:
        print(f"[EMU] Reached instruction cap ({MAX_INSTRUCTIONS})")

    print("\n[VM FINAL STATE]")
    print(f"  r0/ACC    = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_ACC,    CPUSIZE.QWORD)):016x}")
    print(f"  r1        = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_R1,     CPUSIZE.QWORD)):016x}")
    print(f"  r2/RESULT = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_RESULT, CPUSIZE.QWORD)):016x}")
    print(f"  r3/PC     = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_PC,     CPUSIZE.QWORD)):016x}")
    print(f"  r4/NAME   = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_NAME,   CPUSIZE.QWORD)):016x}")
    print(f"  r5/SERIAL = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_SERIAL, CPUSIZE.QWORD)):016x}")
    print(f"  r6/FLAGS  = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_FLAGS,  CPUSIZE.QWORD)):016x}")
    print(f"  r7/SP     = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_SP,     CPUSIZE.QWORD)):016x}")
```

#### Analysis of the Bytecode

Now that we have the emulator working, let's run it and analyze the trace. We start with `NAME_VALUE = b"Pepe\x00"` and `SERIAL_VALUE = b"ABCD1234\x00"`:

```bash
$ python3 solve-vm.py
```

The first thing the VM does is check that neither the name nor the serial pointer is null, then call the strlen routine at `0x0110` on the serial:

```bash
  [VM:0000] CMPZ      r4/NAME
  [VM:0002] JZ        0x0120                   ; FLAGS=0x0
  [VM:0005] CMPZ      r5/SERIAL
  [VM:0007] JZ        0x0120                   ; FLAGS=0x0
  [VM:000a] MOVQ      r0/ACC, r5/SERIAL
  [VM:000d] CALL      0x0110
```

The subroutine at `0x0110` is a standard strlen — it walks the string pointer in `r0` byte by byte until it hits a null terminator, counting the characters in `r1`:

```bash
  [VM:0113] PTR_NULL  r0/ACC
  [VM:0115] JZ        0x011f                   ; FLAGS=0x0
  [VM:0118] INC       r1
  [VM:011a] INC       r0/ACC
  [VM:011c] JMP       0x0113
```

After strlen returns, the length in `r1` is compared against `0x15` (21 in decimal). Our test serial `ABCD1234` is only 8 characters, so it fails immediately:

```bash
  [VM:0010] CMP_IMM8  r1, 0x15             ; FLAGS=0x1
  [VM:0013] JNZ       0x0120                   ; FLAGS=0x2
  [VM:0120] MOV_IMM8  r2/RESULT, 0x00
  [VM:0123] HLT
```

**The serial must be exactly 21 characters.** Let's update it and run again:

```python
SERIAL_VALUE = b"AAAAAAAAAAAAAAAAAAAAA\x00"
```

Now strlen passes, and the VM calls strlen on the name too (storing the result in `r1`), then immediately calls the subroutine at `0x00be` which parses the first two serial characters as a hex digit pair. The parsed value is compared against the name length:

```bash
  [VM:0016] MOVQ      r0/ACC, r4/NAME
  [VM:0019] CALL      0x0110   # strlen(name) -> r1
  [VM:001c] CALL      0x00be   # parse 2 hex chars from serial -> r2
  [VM:001f] CMP_REG   r1, r2/RESULT
  [VM:0022] JNZ       0x0120
```

The subroutine at `0x009a` (called by `0x00be`) validates that each character is a valid hex digit (`0`-`9` or `A`-`F`) and converts it to its numeric value. `0x00be` calls it twice, shifts the first result left by 4 bits, and adds the second to produce a full byte. So **the first two serial characters must be the hex representation of the name length**. For `Pepe` (length 4) that is `04`.

The next check parses two more hex characters and compares them against the sum of the popcount of all characters in the name. The popcount of a byte is the number of set bits in its binary representation:

```bash
  [VM:0025] CALL      0x00ef   # sum of popcount of all name chars -> r1
  [VM:0028] CALL      0x00be   # parse 2 more hex chars -> r2
  [VM:002b] CMP_REG   r1, r2/RESULT
  [VM:002e] JNZ       0x0120
```

For `Pepe`:
- `P` = `0x50` = `01010000b` — 2 set bits
- `e` = `0x65` = `01100101b` — 4 set bits
- `p` = `0x70` = `01110000b` — 3 set bits
- `e` = `0x65` = `01100101b` — 4 set bits
- Total = 13 = `0x0D`

So the second pair of serial characters must be `0D`.

After that, the VM reads one more byte and checks it against `0x2d`, which is the ASCII code for `-`:

```bash
  [VM:0031] LOAD_SERIAL                        ; read next serial byte
  [VM:0032] CMP_IMM8  r0/ACC, 0x2d             ; compare with '-'
  [VM:0035] JNZ       0x0120
```

The serial format so far is `040D-`. We have consumed 5 characters and 16 remain. To keep the trace clean from here, we add the known utility subroutines to a skip list and run with `--no-stdlib`:

```python
SKIP_SUBROUTINES = {
    0x0110,   # strlen
    0x00ce,   # popcount single char
    0x00ef,   # popcount whole string
    0x009a,   # parse hex digit
    0x00be,   # parse hex byte (2 digits)
}
```

#### Reading the 64-bit Serial Value

After the dash separator is consumed, the VM calls subroutine `0x004b`. This one reads the remaining 16 hex characters from the serial and assembles them into a single 64-bit value stored in `ACC`:

```
[VM:0038] CALL      0x004b

[VM:004b] MOV_IMM8  r0/ACC, 0x00    ; r0 = 0 (will hold the result)
[VM:004e] MOV_IMM8  r1, 0x08        ; r1 = 8 (loop counter, one per byte)

; loop:
[VM:0051] CMP_IMM8  r1, 0x00        ; counter == 0?
[VM:0054] JZ        0x0069          ; yes -> done
[VM:0057] PUSH_REG  r0/ACC          ; save current result
[VM:0059] CALL      0x00be          ; parse next 2 hex chars -> r2
[VM:005c] POP_REG   r0/ACC          ; restore result
[VM:005e] SHL       r0/ACC, 0x08    ; shift left 8 bits (make room for new byte)
[VM:0061] MOVB      r0/ACC, r2      ; insert parsed byte into low byte of r0
[VM:0064] DEC       r1              ; counter--
[VM:0066] JMP       0x0051          ; loop back

[VM:0069] RET                       ; r0 = full 64-bit value
```

Each iteration shifts the accumulator left by 8 bits and slots the next parsed byte into the low position. After 8 iterations (16 hex characters) the accumulator holds the complete 64-bit big-endian value.

#### Computing and Comparing the Hash

Once `0x004b` returns, the parsed 64-bit value sits in `r0`. The VM pushes it and calls the hash function at `0x006a`:

```
[VM:003b] PUSH_REG  r0/ACC          ; save the parsed serial value
[VM:003d] CALL      0x006a          ; compute hash(name) -> r2
```

The hash function starts from a fixed constant and processes the name character by character:

```
[VM:006a] MOV_IMM64 r2, 0xb7e151628aed2a6a   ; h = initial constant

; loop -- read one name byte per iteration:
[VM:0074] LOAD_NAME                 ; r0 = next byte from name, advance pointer
[VM:0075] CMPZ      r0/ACC          ; r0 == 0? (end of string)
[VM:0077] JZ        0x0099          ; yes -> done

[VM:007a] PUSH_REG  r2              ; save current hash
[VM:007c] PUSH_REG  r0/ACC          ; save current char
[VM:007e] CALL      0x00ce          ; popcount(r0) -> r2
[VM:0081] MOVQ      r1, r2          ; r1 = popcount(char)
[VM:0084] POP_REG   r0/ACC          ; restore char
[VM:0086] POP_REG   r2              ; restore hash

[VM:0088] ROL       r2, r1          ; h = ROL(h, popcount(char))
[VM:008b] TEST_IMM8 r1, 0x01        ; is popcount odd?
[VM:008e] JZ        0x0093          ; yes -> skip NOT (jump over it)
[VM:0091] NOT       r0/ACC          ; no (even popcount) -> NOT the char byte
[VM:0093] XOR       r2, r0/ACC      ; h ^= char (or ~char)
[VM:0096] JMP       0x0074          ; next character

[VM:0099] RET                       ; r2 = final hash
```

For each character the algorithm does three things — rotates the hash left by the popcount of the character, conditionally NOTs the character byte if that popcount is even, and XORs the result into the hash. The `TEST_IMM8 r1, 0x01` / `JZ 0x0093` pair controls the NOT — when the jump is taken (FLAGS bit0 == 1, meaning `popcount & 1 == 0`, i.e. popcount is even) the NOT is skipped, so only characters with an odd popcount get their byte inverted before the XOR.

After the hash is computed, the final comparison is straightforward:

```
[VM:0040] POP_REG   r0/ACC          ; restore parsed serial value
[VM:0042] CMP_REG   r0, r2          ; serial_value == hash(name)?
[VM:0045] JZ        0x0124          ; yes -> success
[VM:0048] JMP       0x0120          ; no  -> fail

[VM:0124] MOV_IMM8  r2/RESULT, 0x01
[VM:0127] HLT                       ; return 1 -> "Yep, you got it!"

[VM:0120] MOV_IMM8  r2/RESULT, 0x00
[VM:0123] HLT                       ; return 0 -> "Nope, this is incorrect!"
```

The hash computed from the name must exactly match the 64-bit value encoded in the last 16 characters of the serial. If it does, `vm->result` is set to 1 and `vmstart` returns success.

### Writing a Keygen

Now that we know what each field of the serial must contain, we can write a standalone keygen (`keygen.py`) that computes the correct serial for any name:

```python
#!/usr/bin/env python3
"""
VirtUAL 1 serial generator (bagolymadar 2020)
Usage: python3 keygen.py <username>
"""

import sys


def popcount(n: int) -> int:
    return bin(n).count('1')


def compute_hash(name: str) -> int:
    h = 0xb7e151628aed2a6a
    for c in name:
        b   = ord(c)
        pc  = popcount(b) & 63
        h   = ((h << pc) | (h >> (64 - pc))) & 0xffffffffffffffff
        if pc & 1:   # odd popcount -> NOT the char
            b = (~b) & 0xff
        h ^= b
        h &= 0xffffffffffffffff
    return h


def make_serial(name: str) -> str:
    length   = len(name)
    pop_sum  = sum(popcount(ord(c)) for c in name) & 0xff
    hash_val = compute_hash(name)
    return f"{length:02X}{pop_sum:02X}-{hash_val:016X}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 keygen.py <username>")
        sys.exit(1)

    name   = sys.argv[1]
    serial = make_serial(name)

    print(f"Username : {name}")
    print(f"Serial   : {serial}")


if __name__ == "__main__":
    main()
```

Let's run it with `Pepe`:

```bash
$ python3 keygen.py Pepe
Username : Pepe
Serial   : 040D-2A2C515DA54FECE9
```

We can verify the result by putting the serial back into the Triton emulator. The trace should now end with `JZ 0x0124` taken, `r2/RESULT` set to 1, and HLT:

```bash
  [VM:0042] CMP_REG   r0/ACC, r2/RESULT             ; FLAGS=0x1
  [VM:0045] JZ        0x0124                   ; FLAGS=0x1
  [VM:0124] MOV_IMM8  r2/RESULT, 0x01
  [VM:0127] HLT

[VM FINAL STATE]
  r0/ACC    = 0x2a2c515da54fece9
  r1        = 0x0000000000000004
  r2/RESULT = 0x0000000000000001
  r3/PC     = 0x0000000000000127
  r4/NAME   = 0x0000000000200005
  r5/SERIAL = 0x0000000000300015
  r6/FLAGS  = 0x0000000000000001
  r7/SP     = 0x00000000004042f0
```

`r2/RESULT = 0x01` confirms success. And the binary agrees:

```bash
$ ./virtual.1
Username: Pepe
Serial: 040D-2A2C515DA54FECE9

    Yep, you got it!
```

## Conclusion

Code virtualization is a strong protection technique. Even for a relatively simple crackme like this one, we had to build a proper disassembler and emulator before we could read any of the logic. Symbolic execution with Triton and Z3 turned out not to be the right tool here — the serial drives control flow rather than feeding into a single comparison, so there was nothing useful to symbolize. What actually helped was using Triton purely as a concrete emulator and building a VM-level disassembler on top of it, which gave us a clean trace of the bytecode execution.

Once the trace was readable, the algorithm fell out naturally: the serial is 21 characters, the first two encode the name length in hex, the next two encode the total popcount of the name in hex, the fifth is a dash separator, and the remaining sixteen encode a 64-bit hash of the name computed by rotating and XORing with popcount-conditioned byte inversions.

## Extra — Binary Ninja Architecture Plugin

As an extra step, we can take the full opcode table we decoded and use it to write a Binary Ninja architecture plugin (`virtual1_arch.py`). This lets us extract the raw bytecode from the binary, open it as a standalone file in Binary Ninja with the custom architecture selected, and get full disassembly, LLIL lifting, and decompiler output directly — without any of the surrounding x86 code getting in the way.

To extract the bytecode from the open binary in the Binary Ninja scripting console:

```python
bytecode_addr = 0x404108
bytecode_size = 0x200

bytecode = bv.read(bytecode_addr, bytecode_size)
with open("/tmp/vm_bytecode.bin", "wb") as f:
    f.write(bytecode)
```

Open `vm_bytecode.bin` as a Raw binary with the `Virtual1VM` platform selected, press `P` at offset `0x0000` to define the entry point, and let analysis run. The disassembly looks like this:

```c
00000000    void main(int64_t arg1 @ NAME, int64_t arg2 @ SERIAL, int64_t arg3 @ FLAGS) __noreturn
00000000  5404               CMPZ        NAME
00000002  550120             JZ          bad_ending
00000005  5405               CMPZ        SERIAL
00000007  550120             JZ          bad_ending
0000000a  010005             MOVQ        ACC, SERIAL
0000000d  ab0110             CALL        strlen
00000010  7f0115             CMP_IMM8    r1, 0x15
00000013  810120             JNZ         bad_ending
00000016  010004             MOVQ        ACC, NAME
00000019  ab0110             CALL        strlen
0000001c  ab00be             CALL        hexstr_to_hex_number
0000001f  980102             CMP_REG     r1, RESULT
00000022  810120             JNZ         bad_ending
00000025  ab00ef             CALL        bitcount_string
00000028  ab00be             CALL        hexstr_to_hex_number
0000002b  980102             CMP_REG     r1, RESULT
0000002e  810120             JNZ         bad_ending
00000031  52                 LOAD_SERIAL 
00000032  7f002d             CMP_IMM8    ACC, '-'
00000035  810120             JNZ         bad_ending
00000038  ab004b             CALL        str_to_hex
0000003b  8d00               PUSH_REG    ACC {var_10}
0000003d  ab006a             CALL        create_hash_from_name
00000040  8e00               POP_REG     ACC {var_8}
00000042  980002             CMP_REG     ACC, RESULT
00000045  550124             JZ          good_ending
00000048  110120             JMP         bad_ending
```

And the decompiler output for the main entry point:

```c
00000000    void main(int64_t arg1 @ NAME, int64_t arg2 @ SERIAL, int64_t arg3 @ FLAGS) __noreturn
00000000    {
00000000        if (!arg1)
00000002            return bad_ending();
00000007        if (!arg2)
00000007            return bad_ending();
0000000d        int64_t r1 = strlen();
00000013        if (r1 != 0x15)
00000013            return bad_ending();
00000019        int64_t r1_1 = strlen();
0000001c        RESULT = hexstr_to_hex_number();
0000001f        if (r1_1 != RESULT)
00000022            return bad_ending();
00000025        int64_t r1_2 = bitcount_string();
00000028        RESULT_1 = hexstr_to_hex_number();
0000002b        if (r1_2 != RESULT_1)
0000002e            return bad_ending();
00000031        if (ACC_2 != 0x2d)
00000035            return bad_ending();
0000003b        int64_t var_10 = str_to_hex();
0000003d        RESULT_2 = create_hash_from_name();
00000045        if (var_8 == RESULT_2)
00000045            return good_ending();
00000048        return bad_ending();
00000048    }
```

The validation logic that took us some time to read from the raw x86 trace is now expressed clearly by the decompiler, with named functions and readable control flow. The saved Binary Ninja database for the bytecode is included as `vm_bytecode.bin.bndb`.

## Files

| File | Description |
|------|-------------|
| `virtual.1` | The original crackme binary |
| `solve-vm.py` | Triton + LIEF emulator with VM-level disassembler. Run with `--x86` to also print x86 instructions, `--no-stdlib` to suppress output from internal subroutines |
| `keygen.py` | Serial generator — usage: `python3 keygen.py <username>` |
| `virtual1_arch.py` | Binary Ninja architecture plugin for the VM. Copy to `~/.binaryninja/plugins/` and restart Binary Ninja |
| `vm_bytecode.bin` | Raw extracted bytecode, suitable for opening with the architecture plugin |
| `vm_bytecode.bin.bndb` | Binary Ninja database for the bytecode with analysis already applied |


<figure style="text-align: center;">
    <a href="/assets/images/seeu.jpeg">
        <img src="/assets/images/seeu.jpeg">
    </a>
</figure>