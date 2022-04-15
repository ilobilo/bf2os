// Copyright (C) 2022  ilobilo

#pragma once

static const char *prefix = R"(// Copyright (C) 2022  ilobilo

#include <stdint.h>
#include <stddef.h>
#include <limine.h>

static volatile struct limine_terminal_request terminal_request = {
    .id = LIMINE_TERMINAL_REQUEST,
    .revision = 0
};

void putchar(char c)
{
    struct limine_terminal *terminal = terminal_request.response->terminals[0];
    terminal_request.response->write(terminal, &c, 1);
}

char getchar()
{
    return 0;
}

void _start(void)
{
    if (terminal_request.response == NULL || terminal_request.response->terminal_count < 1)
    {
        for (;;) asm volatile ("cli; hlt");
    }

    char array[30000] = { 0 };
    char *ptr = array;

)";

static const char *suffix = R"(
    for (;;) asm volatile ("hlt");
})";

static const char *ccargs = " -std=gnu17 -ffreestanding -fno-stack-protector -fno-omit-frame-pointer -fno-pic -mabi=sysv -mno-80387 -mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-red-zone -mcmodel=kernel -Ilimine/ tmp.c -c -o kernel.o";
static const char *ldargs = " -Tlinker.ld -nostdlib -zmax-page-size=0x1000 -static kernel.o -o kernel.elf";
static const char *cpargs = " kernel.elf limine.cfg limine/limine-cd.bin limine/limine-cd-efi.bin limine/limine.sys iso_root/";
static const char *xorrisoflags = " -as mkisofs -b limine-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot limine-cd-efi.bin -efi-boot-part --efi-boot-image --protective-msdos-label iso_root/ -o ";