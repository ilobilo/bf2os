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

    if (fs::exists(argv[1]) == false)
    {
        std::cout << "File \"" << argv[1] << "\" does not exist!" << std::endl;
        return EXIT_FAILURE;
    }

    fs::create_directories("tmp");

    std::ifstream fin(argv[1]);
    std::ofstream tmpc("tmp/kernel.c");
    std::string spaces("    ");

    tmpc << prefix;

    char ch;
    while (fin >> ch)
    {
        switch (ch)
        {
            case '>':
                tmpc << spaces << "((ptr == &array[29999]) ? ptr = array : ptr++);\n";
                break;
            case '<':
                tmpc << spaces << "((ptr == array) ? ptr = &array[29999] : ptr--);\n";
                break;
            case '+':
                tmpc << spaces << "++*ptr;\n";
                break;
            case '-':
                tmpc << spaces << "--*ptr;\n";
                break;
            case '.':
                tmpc << spaces << "putchar(*ptr);\n";
                break;
            case ',':
                tmpc << spaces << "*ptr = getchar();\n";
                break;
            case '[':
                tmpc << spaces << "while (*ptr)\n";
                tmpc << spaces << "{\n";
                spaces += "    ";
                break;
            case ']':
                spaces.erase(spaces.length() - 4);
                tmpc << spaces << "}\n";
                break;
        }
    }

    tmpc << suffix;

    std::ofstream tmpasm("tmp/kernel.asm");
    tmpasm << kernelasm;
    tmpasm.close();

    fin.close();
    tmpc.close();

    std::string cmd(gnu ? "gcc" : "clang -target x86_64-pc-none-elf");
    cmd += ccargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not compile the kernel!" << std::endl;
        fs::remove_all("tmp");
        return EXIT_FAILURE;
    }

    cmd = "nasm";
    cmd += asmargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not compile the kernel!" << std::endl;
        fs::remove_all("tmp");
        return EXIT_FAILURE;
    }

    cmd = (gnu ? "ld" : "ld.lld");
    cmd += ldargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not link the kernel!" << std::endl;
        fs::remove_all("tmp");
        return EXIT_FAILURE;
    }

    fs::create_directory("tmp/iso_root");

    cmd = "cp";
    cmd += cpargs;
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not create an iso image!" << std::endl;
        fs::remove_all("tmp");
        return EXIT_FAILURE;
    }

    cmd = "xorriso";
    cmd += xorrisoflags;
    cmd += argv[2];
    if (system(cmd.c_str()))
    {
        std::cout << "Unknown error: Could not create an iso image!" << std::endl;
        fs::remove_all("tmp");
        return EXIT_FAILURE;
    }

    fs::remove_all("tmp");

    return EXIT_SUCCESS;
}