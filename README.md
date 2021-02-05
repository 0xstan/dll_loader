# dll_loader

Run a process and inject a dll at startup.

## compilation

`make`

## windows

usage: `./dll_loader binary_to_run.exe ARGS... dll_to_inject.dll`

## linux

usage: `./dll_loader so_to_inject binary ARGS...`. The function `init` in the 
library will be call
