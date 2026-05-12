Proc Mem Analysis tool

Personal tool for in-depth proccess analysis

The tool uses Zydis disassembler to decode shellcode to assembly - you can download download the Zydis source and header file from https://github.com/zyantific/zydis/releases/tag/v4.1.0.

Build commands are:

Initial:
gcc -I. -c Zydis.c -o Zydis.o
g++ -I. -o memiscani.exe memiscani.cpp Zydis.o -lpsapi -static -lgdi32 -mwindows -lcomctl32 -lcomdlg32 -lshell32

On edit:
g++ -I. -o memiscani.exe memiscani.cpp Zydis.o -lpsapi -static -lgdi32 -mwindows -lcomctl32 -lcomdlg32 -lshell32



