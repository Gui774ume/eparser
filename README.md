## EParser

EParser is a simple utility that can be used to dump the eBPF programs and maps of an ELF file.

### System requirements

- golang 1.13+
- This project was developed on an Ubuntu Focal machine (Linux Kernel 5.4) but should be compatible with 4.13+ kernels (not tested).

### Build

1) To build EParser, run:

```shell script
# ~ make build
```

2) To install EParser (copy to /usr/bin/eparser) run:
```shell script
# ~ make install
```

### Getting started

Run `eparser -h` to get help.

```shell script
# ~ eparser -h
Usage:
  eparser [command]

Available Commands:
  help        Help about any command
  map         prints information about one or multiple maps
  prog        prints information about one or multiple programs

Flags:
  -a, --assets string   path to the eBPF assets (ELF format expected)
  -h, --help            help for eparser

Use "eparser [command] --help" for more information about a command.
```

### Examples

#### List all the program sections provided in the ELF file

```shell script
# ~ eparser prog --assets my_elf_file.o
```

#### Dump the bytecode of a program

```shell script
# ~ eparser prog --assets my_elf_file.o --section kprobe/my_program --dump
```

#### List all the map declared in the ELF file

```shell script
# ~ eparser map --assets my_elf_file.o
```
