#### Easy to use, high performance, header only C++ implementation of the ChaCha encryption.
##### Fallback implementation only uses ISO-C++14.

Compile with GCC (or any modern compiler) with
```
g++ -Wall -Wextra -pedantic -std=c++14 -O3 -march=native -o demo.exe demo.cpp
```

Results on my machine (3570k at 4.20 GHz)

With SSSE3 (cycles / byte = 4200000000 / (1436 * 1024 * 1024) = ~2.8):
```
Implementation verified.
ChaCha20    1436 MiB/s          2dedaff3b35afaa7f240cffa33adebba
ChaCha12    2290 MiB/s          ca53ec6c446135fef8f613fab701a355
ChaCha8     3242 MiB/s          557ecf29ef3a43552b8fe637d509e9ca
```

With fallback implementation (cycles / byte = 4200000000 / (519 * 1024 * 1024) = ~7.7):
```
Implementation verified.
ChaCha20    519 MiB/s           a602abc2fdd39ac61daee6f0d12fa60f
ChaCha12    805 MiB/s           e471166c0496a7a3b9f08524d5a80514
ChaCha8     1104 MiB/s          0e7e80925a433625fac6443f8e53a487
```
