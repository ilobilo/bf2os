// Copyright (C) 2022  ilobilo

#include <conflict/conflict.hpp>

#include <filesystem>
#include <fstream>
#include <cstring>

#include <misc.hpp>

namespace fs = std::filesystem;

std::vector<std::string_view> files;
std::string_view limine_path;
uint64_t flags = 0;

const auto parser = conflict::parser
{
    conflict::option { { 'h', "help", "Show help" }, flags, (1 << 0) },
    conflict::option { { 'v', "version", "Show version" }, flags, (1 << 1) },
    conflict::string_option { { 'l', "limine", "Directory containing files: 'limine.h', 'limine-deploy', 'limine-cd.bin', 'limine-cd-efi.bin' and 'limine.sys' (default is './limine')" }, "path", limine_path }
};

void usage(bool err)
{
    auto &out = (err ? std::cerr : std::cout);
    out << "Usage:\n";
    out << "    bf2os -l/--limine path input.bf output.iso\n";
    out << "    CC=cc LD=ld XORRISO=xorriso bf2os input.bf output.iso\n";
}

bool parse_flags()
{
    if (flags & (1 << 0))
    {
        usage(false);
        std::cout << "Options:\n";
        parser.print_help();
        return true;
    }
    else if (flags & (1 << 1))
    {
        std::cout << "bf2c v0.1\n";
        return true;
    }

    return false;
}

fs::path tmpdir;
void cleanup()
{
    fs::remove_all(tmpdir);
};

bool exists(std::string command)
{
    return system((command += " > /dev/null 2>&1").c_str()) != -1;
}

auto get_program(auto env, auto name)
{
    auto ENV = std::getenv(env);
    if (ENV != nullptr && exists(ENV) == true)
        return const_cast<const char*>(ENV);

    if (exists(name) == true)
        return name;

    std::cerr << "Could not find '" << name << "'" << std::endl;
    cleanup();
    std::exit(EXIT_FAILURE);
}

template<typename ...Args>
auto run(Args &&...args)
{
    std::string command;
    auto add = [&command](auto str)
    {
        if (command.empty() == false)
            command += " ";
        command += str;
    };

    (add(std::forward<Args>(args)), ...);
    std::cout << command << std::endl;
    return system(command.c_str());
}

auto main(int argc, char **argv) -> int
{
    parser.apply_defaults();
    conflict::default_report(parser.parse(argc - 1, argv + 1, files));

    if (parse_flags())
        return EXIT_SUCCESS;

    if (files.size() != 2)
    {
        usage(true);
        return EXIT_FAILURE;
    }

    if (limine_path.empty())
        limine_path = "limine";

    auto input_file = files.front();
    auto output_file = files.back();

    if (fs::exists(input_file) == false)
    {
        std::cerr << "File '" << input_file << "' does not exist!" << std::endl;
        return EXIT_FAILURE;
    }

    if (fs::is_regular_file(input_file) == false)
    {
        std::cerr << "'" << input_file << "' is not a regular file!" << std::endl;
        return EXIT_FAILURE;
    }

    if (fs::exists(output_file) && fs::is_regular_file(output_file) == false)
    {
        std::cerr << "'" << output_file << "' is not a regular file!" << std::endl;
        return EXIT_FAILURE;
    }

    if (fs::exists(limine_path) == false || fs::is_directory(limine_path) == false)
    {
        std::cerr << "'" << limine_path << "' is not a directory!" << std::endl;
        return EXIT_FAILURE;
    }

    fs::path limine_dir(limine_path);
    auto limine_h = limine_dir / "limine.h";
    auto limine_deploy = limine_dir / "limine-deploy";
    auto limine_cd = limine_dir / "limine-cd.bin";
    auto limine_cd_efi = limine_dir / "limine-cd-efi.bin";
    auto limine_sys = limine_dir / "limine.sys";

    auto check_exists = [](auto name)
    {
        if (fs::exists(name) == false || fs::is_regular_file(name) == false)
        {
            std::cerr << "'" << name << "' is not a regular file!" << std::endl;
            std::exit(EXIT_FAILURE);
        }
    };

    check_exists(limine_h);
    check_exists(limine_deploy);
    check_exists(limine_cd);
    check_exists(limine_cd_efi);
    check_exists(limine_sys);

    auto cc = get_program("CC", "cc");
    auto ld = get_program("LD", "ld");
    auto xorriso = get_program("XORRISO", "xorriso");

    auto tmplt_path = fs::temp_directory_path() / "bf2os.XXXXXX";
    auto tmplt = strdup(tmplt_path.c_str());

    if (mkdtemp(tmplt) == nullptr)
    {
        std::cerr << "Could not create temporary directory!" << std::endl;
        cleanup();
        std::exit(EXIT_FAILURE);
    }

    tmpdir = tmplt;
    free(tmplt);

    auto kernel_c = tmpdir / "kernel.c";
    auto kernel_c_o = tmpdir / "kernel.c.o";

    auto kernel_S = tmpdir / "kernel.S";
    auto kernel_S_o = tmpdir / "kernel.S.o";

    auto linker_ld = tmpdir / "linker.ld";
    auto iso_root = tmpdir / "iso_root";

    auto kernel_elf = iso_root / "kernel.elf";
    auto limine_cfg = iso_root / "limine.cfg";

    fs::create_directory(iso_root);

    std::ifstream input(input_file.data());
    std::ofstream source(kernel_c);
    source << prefix;

    std::string spaces("    ");
    for (auto c = input.get(); c != EOF; c = input.get())
    {
        switch (c)
        {
            case '>':
                source << spaces << "((ptr == &array[29999]) ? ptr = array : ptr++);\n";
                break;
            case '<':
                source << spaces << "((ptr == array) ? ptr = &array[29999] : ptr--);\n";
                break;
            case '+':
                source << spaces << "++*ptr;\n";
                break;
            case '-':
                source << spaces << "--*ptr;\n";
                break;
            case '.':
                source << spaces << "putchar(*ptr);\n";
                break;
            case ',':
                source << spaces << "*ptr = getchar();\n";
                break;
            case '[':
                source << spaces << "while (*ptr)\n";
                source << spaces << "{\n";
                spaces += "    ";
                break;
            case ']':
                spaces.erase(spaces.length() - 4);
                source << spaces << "}\n";
                break;
        }
    }

    source << suffix;
    source.close();
    input.close();

    std::ofstream(kernel_S) << assembly;
    std::ofstream(linker_ld) << linker;

    if (run(cc, cflags, "-I", limine_dir, kernel_S, "-c -o", kernel_c_o))
    {
        std::cerr << "Could not compile kernel.S!" << std::endl;
        cleanup();
        return EXIT_FAILURE;
    }

    if (run(cc, cflags, "-I", limine_dir, kernel_c, "-c -o", kernel_S_o))
    {
        std::cerr << "Could not compile kernel.c!" << std::endl;
        cleanup();
        return EXIT_FAILURE;
    }

    if (run(ld, ldflags, "-T", linker_ld, kernel_S_o, kernel_c_o, "-o", kernel_elf))
    {
        std::cerr << "Could not link the kernel!" << std::endl;
        cleanup();
        return EXIT_FAILURE;
    }

    std::ofstream(limine_cfg) << config;

    fs::copy_file(limine_cd, iso_root / "limine-cd.bin");
    fs::copy_file(limine_cd_efi, iso_root / "limine-cd-efi.bin");
    fs::copy_file(limine_sys, iso_root / "limine.sys");

    if (run(xorriso, xorrisoflags, iso_root, "-o", output_file))
    {
        std::cerr << "Could not create kernel iso!" << std::endl;
        cleanup();
        return EXIT_FAILURE;
    }

    if (run(limine_deploy, output_file))
    {
        std::cerr << "Could not deploy limine to kernel iso!" << std::endl;
        cleanup();
        return EXIT_FAILURE;
    }

    cleanup();
    return EXIT_SUCCESS;
}