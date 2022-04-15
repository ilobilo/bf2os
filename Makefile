CPP = clang++
TARGET = bf2os

CPPFLAGS = -std=gnu++20 -I. -Wall -Werror -Wextra

MAINCPP = main.cpp

all: limine $(TARGET)

$(TARGET): clean
	$(CPP) $(CPPFLAGS) $(MAINCPP) -o $(TARGET)

limine:
	git clone --single-branch --branch=v3.0-branch-binary --depth=1 https://github.com/limine-bootloader/limine
	$(MAKE) -C limine

clean:
	rm -f $(TARGET)

distclean:
	rm -rf limine $(TARGET)