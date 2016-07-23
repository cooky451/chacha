####Easy to use, high performance, header only C++ implementation of the ChaCha encryption.

Compile with GCC (or any modern compiler) with
```
g++ -Wall -Wextra -pedantic -std=c++14 -O3 -march=native -o demo.exe demo.cpp
```

Results on my machine (3570k at 4.20 GHz) (SSE results can vary a bit on Windows, these are with increased process priority.)

With SSE3 (cycles / byte = 4200000000 / (1424.31 * 1024 * 1024) = ~2.8):
```
Implementation verified.
ChaCha20 bandwidth: 1424.31 MiB/s               c17c5d0d964d4b665f3632782074b0fd
ChaCha12 bandwidth: 2290.31 MiB/s               6a07031e518028ff0c90dfd72af948ae
ChaCha8 bandwidth: 2944.79 MiB/s                fb5fde40daa5c02e13ab59de4a00e6f5
```

With fallback implementation (cycles / byte = 4200000000 / (516.443 * 1024 * 1024) = ~7.8):
```
Implementation verified.
ChaCha20 bandwidth: 516.443 MiB/s               c17c5d0d964d4b665f3632782074b0fd
ChaCha12 bandwidth: 775.747 MiB/s               6a07031e518028ff0c90dfd72af948ae
ChaCha8 bandwidth: 1029.19 MiB/s                fb5fde40daa5c02e13ab59de4a00e6f5
```
