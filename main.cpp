// Copyright (C) 2022  ilobilo

#include <filesystem>
#include <iostream>
#include <fstream>
#include <cstring>

#include <misc.hpp>

namespace fs = std::filesystem;

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cout << "Usage:" << std::endl;
        std::cout << "  bf2os in.bf out.iso" << std::endl;
        std::cout << "Default compiler is clang and linker is ld.lld, to use gcc and ld add \"gnu\" flag to the command line:" << std::endl;
        std::cout << "  bf2os in.bf out.iso gnu" << std::endl;
        return EXIT_FAILURE;
    }
    bool gnu = false;
    if (argc >= 4 && !std::strcmp(argv[3], "gnu")) gnu = true;

    std::ifstream fin(argv[1]);
    std::ofstream tmp("tmp.c");
    std::string spaces("    ");

    tmp << prefix;

    char ch;
    while (fin >> ch)
    {
        switch (ch)
        {
            case '>':
                tmp << spaces << "((ptr == &array[29999]) ? ptr = array : ptr++);\n";
                break;
            case '<':
                tmp << spaces << "((ptr == array) ? ptr = &array[29999] : ptr--);\n";
                break;
            case '+':
                tmp << spaces << "++*ptr;\n";
                break;
            case '-':
                tmp << spaces << "--*ptr;\n";
                break;
            case '.':
                tmp << spaces << "putchar(*ptr);\n";
                break;
            case ',':
                tmp << spaces << "*ptr = getchar();\n";
                break;
            case '[':
                tmp << spaces << "while (*ptr)\n";
                tmp << spaces << "{\n";
                spaces += "    ";
                break;
            case ']':
                spaces.erase(spaces.length() - 4);
                tmp << spaces << "}\n";
                break;
        }
    }

    tmp << suffix;

    fin.close();
    tmp.close();

    std::string cmd(gnu ? "gcc" : "clang -target x86_64-pc-none-elf");
    cmd += ccargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not compile the kernel!" << std::endl;
        return EXIT_FAILURE;
    }

    cmd = (gnu ? "ld" : "ld.lld");
    cmd += ldargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not link the kernel!" << std::endl;
        fs::remove("kernel.o");
        fs::remove("tmp.c");
        return EXIT_FAILURE;
    }

    fs::remove("tmp.c");
    fs::remove("kernel.o");
    fs::create_directory("iso_root");

    cmd = "cp";
    cmd += cpargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not create an iso image!" << std::endl;
        fs::remove("kernel.elf");
        return EXIT_FAILURE;
    }
    fs::remove("kernel.elf");

    cmd = "xorriso";
    cmd += xorrisoflags;
    cmd += argv[2];
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not create an iso image!" << std::endl;
        return EXIT_FAILURE;
    }

    fs::remove_all("iso_root");

    return EXIT_SUCCESS;
}