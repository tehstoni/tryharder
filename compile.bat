@echo off

set SOURCE_FILE=main.cpp
set OUTPUT_FILE=main.exe

cl /O2 /Ob2 /Os /Gs- /Zi /EHsc- /GL /Os /GF /Gy /GA %SOURCE_FILE% /Fe%OUTPUT_FILE%

rm -f *.obj *.pdb