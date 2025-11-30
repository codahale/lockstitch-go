# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 25436862             47.34 ns/op                             224 B/op          1 allocs/op
BenchmarkMix-4                  23882565             49.22 ns/op                              24 B/op          1 allocs/op
BenchmarkDerive-4                1359247             887.7 ns/op                            1656 B/op         11 allocs/op
BenchmarkEncrypt-4                727957              1507 ns/op                            3272 B/op         17 allocs/op
BenchmarkDecrypt-4                841549              1499 ns/op                            3272 B/op         17 allocs/op
BenchmarkSeal-4                   681934              1782 ns/op                            3560 B/op         19 allocs/op
BenchmarkOpen-4                   661084              1849 ns/op                            3784 B/op         20 allocs/op
BenchmarkHash/16B-4              1230864             977.0 ns/op          16.38 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/256B-4              875114              1350 ns/op         189.61 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/1KiB-4              503163              2380 ns/op         430.22 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/16KiB-4              51012             23461 ns/op         698.34 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/1MiB-4                 847           1431249 ns/op         732.63 MB/s        1952 B/op         14 allocs/op
BenchmarkPRF/16B-4               1221116             982.5 ns/op          16.29 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/256B-4              1223367             978.9 ns/op         261.53 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/1KiB-4              1000000              1100 ns/op         931.01 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/16KiB-4              390930              3094 ns/op        5295.71 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/1MiB-4                 8090            151640 ns/op        6914.89 MB/s        1912 B/op         13 allocs/op
BenchmarkStream/16B-4             497142              2157 ns/op           7.42 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/256B-4            542275              2183 ns/op         117.27 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/1KiB-4            518016              2366 ns/op         432.85 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/16KiB-4           215466              5513 ns/op        2971.97 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/1MiB-4              5280            214089 ns/op        4897.86 MB/s        3552 B/op         20 allocs/op
BenchmarkAEAD/16B-4               456505              2551 ns/op          12.54 MB/s        3864 B/op         23 allocs/op
BenchmarkAEAD/256B-4              397988              2559 ns/op         106.30 MB/s        3864 B/op         23 allocs/op
BenchmarkAEAD/1KiB-4              431269              2709 ns/op         383.87 MB/s        3864 B/op         23 allocs/op
BenchmarkAEAD/16KiB-4             225962              5439 ns/op        3015.21 MB/s        3864 B/op         23 allocs/op
BenchmarkAEAD/1MiB-4                5646            214257 ns/op        4894.08 MB/s        3864 B/op         23 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7`, M4 Pro, macOS 26.1, Go 1.25.4)

```text
goos: darwin
goarch: arm64
pkg: github.com/codahale/lockstitch-go
cpu: Apple M4 Pro
BenchmarkInit-14                        40206490             29.99 ns/op                             224 B/op          1 allocs/op
BenchmarkMix-14                         41024296             27.83 ns/op                              24 B/op          1 allocs/op
BenchmarkDerive-14                       2444509             487.4 ns/op                            1656 B/op         11 allocs/op
BenchmarkEncrypt-14                      1378604             867.8 ns/op                            3272 B/op         17 allocs/op
BenchmarkDecrypt-14                      1379739             868.5 ns/op                            3272 B/op         17 allocs/op
BenchmarkSeal-14                         1215902             986.9 ns/op                            3560 B/op         19 allocs/op
BenchmarkOpen-14                         1000000              1040 ns/op                            3784 B/op         20 allocs/op
BenchmarkHash/16B-14                     2190976             546.0 ns/op          29.30 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/256B-14                    1758662             680.2 ns/op         376.36 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/1KiB-14                    1000000              1091 ns/op         938.51 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/16KiB-14                    128137              9273 ns/op        1766.85 MB/s        1952 B/op         14 allocs/op
BenchmarkHash/1MiB-14                       2113            559161 ns/op        1875.27 MB/s        1952 B/op         14 allocs/op
BenchmarkPRF/16B-14                      2221782             535.8 ns/op          29.86 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/256B-14                     2161114             552.8 ns/op         463.12 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/1KiB-14                     1925991             619.6 ns/op        1652.66 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/16KiB-14                     571784              2028 ns/op        8079.65 MB/s        1912 B/op         13 allocs/op
BenchmarkPRF/1MiB-14                       12537             95658 ns/op       10961.66 MB/s        1912 B/op         13 allocs/op
BenchmarkStream/16B-14                   1000000              1145 ns/op          13.97 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/256B-14                   998307              1165 ns/op         219.71 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/1KiB-14                   898443              1290 ns/op         793.60 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/16KiB-14                  309420              3804 ns/op        4306.57 MB/s        3552 B/op         20 allocs/op
BenchmarkStream/1MiB-14                     6736            174464 ns/op        6010.26 MB/s        3552 B/op         20 allocs/o
BenchmarkAEAD/16B-14                      886958              1277 ns/op          25.06 MB/s        3864 B/op         23 allocs/o
BenchmarkAEAD/256B-14                     903625              1296 ns/op         209.80 MB/s        3864 B/op         23 allocs/o
BenchmarkAEAD/1KiB-14                     828916              1421 ns/op         731.94 MB/s        3864 B/op         23 allocs/o
BenchmarkAEAD/16KiB-14                    309186              3807 ns/op        4307.65 MB/s        3864 B/op         23 allocs/o
BenchmarkAEAD/1MiB-14                       6712            174294 ns/op        6016.24 MB/s        3864 B/op         23 allocs/o
```
