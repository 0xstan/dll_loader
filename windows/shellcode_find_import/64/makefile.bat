..\..\nasm\nasm-2.14.02\nasm.exe -f win64 test.asm -o test.obj
..\..\Golink\GoLink.exe test.obj /console /mix /entry _start kernel32.dll
rm test.obj
