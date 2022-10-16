# Bf2os
Boot your Brainfuck program

## Building and Running
* This repository contains limine binary branch submodule. To use it, please clone this repo with --recursive flag
* ``meson builddir``
* ``ninja -C builddir``
* ``./builddir/bf2os -l/--limine path input.bf output.iso``
* Limine directory should contain files: ``limine.h``, ``limine-deploy``, ``limine-cd.bin``, ``limine-cd-efi.bin`` and ``limine.sys``
* Default path is ``./limine``
* You can also use custom CC, LD and XORRISO with environment variables