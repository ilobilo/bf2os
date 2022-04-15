# bf2os
Boot your Brainfuck program

* Run ```make``` to compile
* Default compiler is clang++, specify custom one with CPP=MyCompiler (e.g. g++)
* Usage: ./bf2os in.bf out.iso
* Default OS compilers are nasm and clang and linker is ld.lld, to use gcc and ld add "gnu" flag to the command line. for example: ./bf2os in.bf out.iso gnu