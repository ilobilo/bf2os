// Copyright (C) 2022  ilobilo

#pragma once

static const char *prefix = R"(// Copyright (C) 2022  ilobilo

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <limine.h>

static volatile struct limine_terminal_request terminal_request = {
    .id = LIMINE_TERMINAL_REQUEST,
    .revision = 0
};

size_t strlen(const char *str)
{
    if (str == NULL) return 0;
    size_t length = 0;
    while (str[length]) length++;
    return length;
}

void print(const char *str)
{
    struct limine_terminal *terminal = terminal_request.response->terminals[0];
    terminal_request.response->write(terminal, str, strlen(str));
}

void outb(uint16_t port, uint8_t val)
{
    asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

uint8_t inb(uint16_t port)
{
    uint8_t data;
    asm volatile("inb %w1, %b0" : "=a" (data) : "Nd" (port));
    return data;
}

struct idt_entry
{
    uint16_t Offset1;
    uint16_t Selector;
    uint8_t IST;
    uint8_t TypeAttr;
    uint16_t Offset2;
    uint32_t Offset3;
    uint32_t Zero;
} __attribute__((packed));
struct idt_entry idt[256];

struct idt_ptr
{
    uint16_t Limit;
    uint64_t Base;
} __attribute__((packed));
struct idt_ptr idtr;

struct registers_t
{
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no, error_code, rip, cs, rflags, rsp, ss;
} __attribute__((packed));

static const char *exception_messages[32] = {
    "Division by zero",
    "Debug",
    "Non-maskable interrupt",
    "Breakpoint",
    "Detected overflow",
    "Out-of-bounds",
    "Invalid opcode",
    "No coprocessor",
    "Double fault",
    "Coprocessor segment overrun",
    "Bad TSS",
    "Segment not present",
    "Stack fault",
    "General protection fault",
    "Page fault",
    "Unknown interrupt",
    "Coprocessor fault",
    "Alignment check",
    "Machine check",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
};

#define CAPSLOCK 0x3A
#define NUMLOCK 0x45
#define SCROLLLOCK 0x46

#define L_SHIFT_DOWN 0x2A
#define R_SHIFT_DOWN 0x36
#define L_SHIFT_UP 0xAA
#define R_SHIFT_UP 0xB6

#define CTRL_DOWN 0x1D
#define CTRL_UP 0x9D

#define ALT_DOWN 0x38
#define ALT_UP 0xB8

#define UP 0x48
#define DOWN 0x50
#define LEFT 0x4B
#define RIGHT 0x4D

unsigned char kbdus[128] =
{
	0,  27, '1', '2', '3', '4', '5', '6', '7', '8',	/* 9 */
	'9', '0', '-', '=', '\b',	/* Backspace */
	'\t',			/* Tab */
	'q', 'w', 'e', 'r',	/* 19 */
	't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',	/* Enter key */
	0,			/* 29   - Control */
	'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',	/* 39 */
	'\'', '`',   0,		/* Left shift */
	'\\', 'z', 'x', 'c', 'v', 'b', 'n',			/* 49 */
	'm', ',', '.', '/',   0,				/* Right shift */
	'*',
	0,	/* Alt */
	' ',	/* Space bar */
	0,	/* Caps lock */
	0,	/* 59 - F1 key ... > */
	0,   0,   0,   0,   0,   0,   0,   0,
	0,	/* < ... F10 */
	0,	/* 69 - Num lock*/
	0,	/* Scroll Lock */
	0,	/* Home key */
	0,	/* Up Arrow */
	0,	/* Page Up */
	'-',
	0,	/* Left Arrow */
	0,
	0,	/* Right Arrow */
	'+',
	0,	/* 79 - End key*/
	0,	/* Down Arrow */
	0,	/* Page Down */
	0,	/* Insert Key */
	0,	/* Delete Key */
	0,   0,   0,
	0,	/* F11 Key */
	0,	/* F12 Key */
0,	/* All other keys are undefined */
};

unsigned char kbdus_shft[128] =
{
	0,  27, '!', '@', '#', '$', '%', '^', '&', '*',	/* 9 */
	'(', ')', '_', '+', '\b',	/* Backspace */
	'\t',			/* Tab */
	'Q', 'W', 'E', 'R',	/* 19 */
	'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',	/* Enter key */
	0,			/* 29   - Control */
	'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',	/* 39 */
	'\"', '~',   0,		/* Left shift */
	'|', 'Z', 'X', 'C', 'V', 'B', 'N',			/* 49 */
	'M', '<', '>', '?',   0,				/* Right shift */
	'*',
	0,	/* Alt */
	' ',	/* Space bar */
	0,	/* Caps lock */
	0,	/* 59 - F1 key ... > */
	0,   0,   0,   0,   0,   0,   0,   0,
	0,	/* < ... F10 */
	0,	/* 69 - Num lock*/
	0,	/* Scroll Lock */
	0,	/* Home key */
	0,	/* Up Arrow */
	0,	/* Page Up */
	'-',
	0,	/* Left Arrow */
	0,
	0,	/* Right Arrow */
	'+',
	0,	/* 79 - End key*/
	0,	/* Down Arrow */
	0,	/* Page Down */
	0,	/* Insert Key */
	0,	/* Delete Key */
	0,   0,   0,
	0,	/* F11 Key */
	0,	/* F12 Key */
	0,	/* All other keys are undefined */
};

unsigned char kbdus_caps[128] =
{
	0,  27, '1', '2', '3', '4', '5', '6', '7', '8',	/* 9 */
	'9', '0', '-', '=', '\b',	/* Backspace */
	'\t',			/* Tab */
	'Q', 'W', 'E', 'R',	/* 19 */
	'T', 'Y', 'U', 'I', 'O', 'P', '[', ']', '\n',	/* Enter key */
	0,			/* 29   - Control */
	'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ';',	/* 39 */
	'\'', '`',   0,		/* Left shift */
	'\\', 'Z', 'X', 'C', 'V', 'B', 'N',			/* 49 */
	'M', ',', '.', '/',   0,				/* Right shift */
	'*',
	0,	/* Alt */
	' ',	/* Space bar */
	0,	/* Caps lock */
	0,	/* 59 - F1 key ... > */
	0,   0,   0,   0,   0,   0,   0,   0,
	0,	/* < ... F10 */
	0,	/* 69 - Num lock*/
	0,	/* Scroll Lock */
	0,	/* Home key */
	0,	/* Up Arrow */
	0,	/* Page Up */
	'-',
	0,	/* Left Arrow */
	0,
	0,	/* Right Arrow */
	'+',
	0,	/* 79 - End key*/
	0,	/* Down Arrow */
	0,	/* Page Down */
	0,	/* Insert Key */
	0,	/* Delete Key */
	0,   0,   0,
	0,	/* F11 Key */
	0,	/* F12 Key */
	0,	/* All other keys are undefined */
};

unsigned char kbdus_capsshft[128] =
{
	0,  27, '!', '@', '#', '$', '%', '^', '&', '*',     /* 9 */
	'(', ')', '_', '+', '\b',     /* Backspace */
	'\t',                 /* Tab */
	'q', 'w', 'e', 'r',   /* 19 */
	't', 'y', 'u', 'i', 'o', 'p', '{', '}', '\n', /* Enter key */
	0,                  /* 29   - Control */
	'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ':',     /* 39 */
	'\"', '~',   0,                /* Left shift */
	'|', 'z', 'x', 'c', 'v', 'b', 'n',                     /* 49 */
	'm', '<', '>', '?',   0,                              /* Right shift */
	'*',
	0,  /* Alt */
	' ',  /* Space bar */
	0,  /* Caps lock */
	0,  /* 59 - F1 key ... > */
	0,   0,   0,   0,   0,   0,   0,   0,
	0,  /* < ... F10 */
	0,  /* 69 - Num lock*/
	0,  /* Scroll Lock */
	0,  /* Home key */
	0,  /* Up Arrow */
	0,  /* Page Up */
	'-',
	0,  /* Left Arrow */
	0,
	0,  /* Right Arrow */
	'+',
	0,  /* 79 - End key*/
	0,  /* Down Arrow */
	0,  /* Page Down */
	0,  /* Insert Key */
	0,  /* Delete Key */
	0,   0,   0,
	0,  /* F11 Key */
	0,  /* F12 Key */
	0,  /* All other keys are undefined */
};

struct kbd_mod_t
{
    bool shift : 1;
    bool ctrl : 1;
    bool alt : 1;
    bool numlock : 1;
    bool capslock : 1;
    bool scrolllock : 1;
};
struct kbd_mod_t kbd_mod;

volatile bool pressed = false;
char c[2] = { 0 };

char getchar()
{
    while (!pressed);
    pressed = false;
    print(c);
    return c[0];
}

char get_ascii_char(uint8_t key_code)
{
    if (!kbd_mod.shift && !kbd_mod.capslock)
        return kbdus[key_code];
    else if (kbd_mod.shift && !kbd_mod.capslock)
        return kbdus_shft[key_code];
    else if (!kbd_mod.shift && kbd_mod.capslock)
        return kbdus_caps[key_code];
    else if (kbd_mod.shift && kbd_mod.capslock)
        return kbdus_capsshft[key_code];

    return 0;
}

bool wait_in()
{
    uint64_t timeout = 100000U;
    while (--timeout)
        if (!(inb(0x64) & (1 << 1)))
            return false;
    return true;
}

bool wait_out()
{
	uint64_t timeout = 100000;
	while (--timeout)
        if (inb(0x64) & (1 << 0))
            return false;
	return true;
}

uint8_t kbd_write(uint8_t write)
{
	wait_in();
	outb(0x60, write);
	wait_out();
	return inb(0x60);
}

void update_leds()
{
    uint8_t value = 0b000;

    if (kbd_mod.scrolllock)
        value |= (1 << 0);
    if (kbd_mod.numlock)
        value |= (1 << 1);
    if (kbd_mod.capslock)
        value |= (1 << 2);

    kbd_write(0xED);
    kbd_write(value);
}

void kbd_handler(struct registers_t *regs)
{
    uint8_t scancode = inb(0x60);

    if (scancode & 0x80)
    {
        switch (scancode)
        {
            case L_SHIFT_UP:
            case R_SHIFT_UP:
                kbd_mod.shift = false;
                break;
            case CTRL_UP:
                kbd_mod.ctrl = false;
                break;
            case ALT_UP:
                kbd_mod.alt = false;
                break;
        }
    }
    else
    {
        switch (scancode)
        {
            case L_SHIFT_DOWN:
            case R_SHIFT_DOWN:
                kbd_mod.shift = true;
                break;
            case CTRL_DOWN:
                kbd_mod.ctrl = true;
                break;
            case ALT_DOWN:
                kbd_mod.alt = true;
                break;
            case CAPSLOCK:
                kbd_mod.capslock = (!kbd_mod.capslock) ? true : false;
                update_leds();
                break;
            case NUMLOCK:
                kbd_mod.numlock = (!kbd_mod.numlock) ? true : false;
                update_leds();
                break;
            case SCROLLLOCK:
                kbd_mod.scrolllock = (!kbd_mod.scrolllock) ? true : false;
                update_leds();
                break;
            case UP:
                print("\033[A");
                break;
            case DOWN:
                print("\033[B");
                break;
            case RIGHT:
                print("\033[C");
                break;
            case LEFT:
                print("\033[D");
                break;
            default:
                c[0] = get_ascii_char(scancode);
                if (kbd_mod.ctrl && (c[0] == 'l' || c[0] == 'L'))
                {
                    print("\033[H\033[2J");
                    break;
                }
                pressed = true;
                // print(c);
                break;
        }
    }
}

typedef void (*isr_t)(struct registers_t*);
isr_t interrupt_handlers[256];
extern void *int_table[];

void idt_set_descriptor(uint8_t vector, void *isr)
{
    idt[vector].Offset1 = (uint64_t)isr;
    idt[vector].Selector = 0x28;
    idt[vector].IST = 0;
    idt[vector].TypeAttr = 0x8E;
    idt[vector].Offset2 = (uint64_t)isr >> 16;
    idt[vector].Offset3 = (uint64_t)isr >> 32;
    idt[vector].Zero = 0;
}

void register_interrupt_handler(uint8_t vector, isr_t handler)
{
    interrupt_handlers[vector] = handler;
}

void exception_handler(struct registers_t *regs)
{
    print("\nSystem Exception!\n");
    print(exception_messages[regs->int_no]);

    for (;;)
        asm volatile ("cli; hlt");
}

void irq_handler(struct registers_t *regs)
{
    if (interrupt_handlers[regs->int_no])
        interrupt_handlers[regs->int_no](regs);

    if (regs->int_no >= 40)
        outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

void int_handler(struct registers_t *regs)
{
    if (regs->int_no < 32)
        exception_handler(regs);
    else if (regs->int_no >= 32 && regs->int_no < 256)
        irq_handler(regs);
}

void idt_init()
{
    idtr.Limit = sizeof(struct idt_entry) * 256 - 1;
    idtr.Base = (uintptr_t)&idt[0];

    for (size_t i = 0; i < 256; i++)
        idt_set_descriptor(i, int_table[i]);

    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    outb(0x21, 0x20);
    outb(0xA1, 0x28);
    outb(0x21, 0x04);
    outb(0xA1, 0x02);
    outb(0x21, 0x01);
    outb(0xA1, 0x01);
    outb(0x21, 0x00);
    outb(0xA1, 0x00);

    asm volatile ("cli");
    asm volatile ("lidt %0" : : "memory"(idtr));
    asm volatile ("sti");
}

void ps2_init()
{
    register_interrupt_handler(33, kbd_handler);
}

void putchar(char c)
{
    struct limine_terminal *terminal = terminal_request.response->terminals[0];
    terminal_request.response->write(terminal, &c, 1);
}

void _start(void)
{
    if (terminal_request.response == NULL || terminal_request.response->terminal_count < 1)
        for (;;)
            asm volatile ("cli; hlt");

    idt_init();
    ps2_init();

    char array[30000];
    char *ptr = array;

)";

static const char *suffix = R"(
    for (;;)
        asm volatile ("hlt");
})";

static const char *kernelasm = R"(; Copyright (C) 2022  ilobilo

%macro pushall 0
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro popall 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

[EXTERN int_handler]
int_common_stub:
    pushall
    mov rdi, rsp
    call int_handler
    popall
    add rsp, 16
    iretq

%macro isr 1
isr_%1:
%if !(%1 == 8 || (%1 >= 10 && %1 <= 14) || %1 == 17 || %1 == 21 || %1 == 29 || %1 == 30)
    push 0
%endif
    push %1
    jmp int_common_stub
%endmacro

%assign i 0
%rep 256
isr i
%assign i i+1
%endrep

section .data
int_table:
%assign i 0
%rep 256
    dq isr_%+i
%assign i i+1
%endrep
[GLOBAL int_table]

memset:
    push rdi
    mov rax, rsi
    mov rcx, rdx
    rep stosb
    pop rax
    ret
[GLOBAL memset]
)";

static const char *ccargs = " -std=gnu17 -ffreestanding -fno-stack-protector -fno-omit-frame-pointer -fno-pic -mabi=sysv -mno-80387 -mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-red-zone -mcmodel=kernel -I. -Ilimine tmp/*.c -c -o tmp/kernel.o";
static const char *ldargs = " -Tlinker.ld -nostdlib -zmax-page-size=0x1000 -static tmp/kernel.o tmp/kernelasm.o -o tmp/kernel.elf";
static const char *cpargs = " tmp/kernel.elf limine.cfg limine/limine-cd.bin limine/limine-cd-efi.bin limine/limine.sys tmp/iso_root";
static const char *xorrisoflags = " -as mkisofs -b limine-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot limine-cd-efi.bin -efi-boot-part --efi-boot-image --protective-msdos-label tmp/iso_root -o ";
static const char *asmargs = " -felf64 -o tmp/kernelasm.o tmp/*.asm";