# Proc Mem Analysis tool - Memiscani — Full install

## Features - Memory analysis and modification tools with workflow support

<img width="1900" height="1000" alt="memiscani1" src="https://github.com/user-attachments/assets/44d3963a-6abb-426e-aca4-9bb4b851ab97" />

<img width="1900" height="1000" alt="memiscani2" src="https://github.com/user-attachments/assets/cdff40e4-829a-40cf-ba01-4b5daeb5a192" />



## 1. Install MinGW-w64 (the C/C++ compiler)

The build needs `gcc`, `g++`, and `ar` (the archiver) in `PATH`.  Pick
**one** of the options below.


## 2. Create project folder

At minimum you need these files / directories in the project root:

```
memiscani_im.cpp
memcore.cpp / memcore.h
mem_lua.cpp / mem_lua.h
Zydis.c / Zydis.h
build.bat
```

You do **not** need to get `imgui\` or `lua54\` — `build.bat setup`
will clone them.

The tool uses Zydis disassembler to decode - so you must download the Zydis source and header file from https://github.com/zyantific/zydis/releases/tag/v4.1.0.

---

## 3. One-time setup

From the project root in `cmd`:

```cmd
build.bat setup
```

This does, in order:

1. Creates `build\`, `obj\`, and `obj\lua\`.
2. **Clones Dear ImGui v1.91.5** into `imgui\` (~10 MB git clone).
3. **Clones Lua 5.4.7** into `lua54\` (~3 MB git clone).
4. Compiles `Zydis.c` → `obj\Zydis.o`.
5. Compiles 32 Lua source files → `obj\lua\*.o`, then archives them
   into `obj\liblua54.a`.


## 4. Pre-compile ImGui (one-time)

```cmd
build.bat imgui
```

## 5. Build

```cmd
build.bat full
```
