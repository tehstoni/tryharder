@echo off

set SOURCE_FILE=main.cpp
set OUTPUT_FILE=main.exe

cl /EHsc /O2 %SOURCE_FILE% /Fe%OUTPUT_FILE%