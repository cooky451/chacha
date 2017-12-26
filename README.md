#### High performance, header only C++ implementation of the ChaCha encryption.
##### Fallback implementation only uses ISO-C++17.

Compile with GCC (or any modern compiler) with
```
g++ -std=c++17 -pedantic -Wall -O3 -march=corei7 -o demo.exe demo.cpp
```

Results on a 8700K at 4.7 GHz

With SSSE3 (cycles / byte = 4700000000 / (1705 * 1024 * 1024) = ~2.6):
```
All tests successful.
Running benchmarks for 1.5 seconds with buffer size [2097152] including stream xor...
Name            Bandwidth               NoOptTag
Chacha20        1705 MiB/s              0bc8f2524959531a9bcaa3cff9628907
Chacha12        2790 MiB/s              736db4830ac4c4a214f343aa1d3e2178
Chacha8         4049 MiB/s              fee4b06a7c6abd46005f18b3b507a54c
```

With fallback implementation (cycles / byte = 4700000000 / (735 * 1024 * 1024) = ~6.1):
```
All tests successful.
Running benchmarks for 1.5 seconds with buffer size [2097152] including stream xor...
Name            Bandwidth               NoOptTag
Chacha20        735 MiB/s               0bc8f2524959531a9bcaa3cff9628907
Chacha12        1195 MiB/s              736db4830ac4c4a214f343aa1d3e2178
Chacha8         1578 MiB/s              fee4b06a7c6abd46005f18b3b507a54c
```
