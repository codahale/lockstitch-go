# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 19886361              58.13 ns/op                            224 B/op          1 allocs/op
BenchmarkMix-4                  11087223             108.8 ns/op                              48 B/op          4 allocs/op
BenchmarkDerive-4                1000000              1121 ns/op                            1696 B/op         20 allocs/op
BenchmarkEncrypt-4                610932              1892 ns/op                            3328 B/op         29 allocs/op
BenchmarkDecrypt-4                634032              1897 ns/op                            3328 B/op         29 allocs/op
BenchmarkSeal-4                   514482              2322 ns/op                            3656 B/op         36 allocs/op
BenchmarkOpen-4                   499848              2429 ns/op                            3896 B/op         38 allocs/op
BenchmarkHash/16B-4               763161              1339 ns/op          11.95 MB/s        2000 B/op         26 allocs/op
BenchmarkHash/256B-4              694984              1736 ns/op         147.44 MB/s        2000 B/op         26 allocs/op
BenchmarkHash/1KiB-4              403371              2987 ns/op         342.85 MB/s        2000 B/op         26 allocs/op
BenchmarkHash/16KiB-4              42706             27856 ns/op         588.16 MB/s        2000 B/op         26 allocs/op
BenchmarkHash/1MiB-4                 712           1688899 ns/op         620.86 MB/s        2000 B/op         26 allocs/op
BenchmarkPRF/16B-4                802160              1320 ns/op          12.12 MB/s        1968 B/op         25 allocs/op
BenchmarkPRF/256B-4               878008              1339 ns/op         191.16 MB/s        1968 B/op         25 allocs/op
BenchmarkPRF/1KiB-4               790542              1423 ns/op         719.46 MB/s        1968 B/op         25 allocs/op
BenchmarkPRF/16KiB-4              352041              3280 ns/op        4994.58 MB/s        1968 B/op         25 allocs/op
BenchmarkPRF/1MiB-4                 8643            141048 ns/op        7434.15 MB/s        1968 B/op         25 allocs/op
BenchmarkStream/16B-4             397081              2797 ns/op           5.72 MB/s        3648 B/op         38 allocs/op
BenchmarkStream/256B-4            425001              2824 ns/op          90.64 MB/s        3648 B/op         38 allocs/op
BenchmarkStream/1KiB-4            374869              3003 ns/op         341.03 MB/s        3648 B/op         38 allocs/op
BenchmarkStream/16KiB-4           196225              6074 ns/op        2697.24 MB/s        3648 B/op         38 allocs/op
BenchmarkStream/1MiB-4              5667            212229 ns/op        4940.77 MB/s        3648 B/op         38 allocs/op
BenchmarkAEAD/16B-4               339718              3334 ns/op           9.60 MB/s        4024 B/op         49 allocs/op
BenchmarkAEAD/256B-4              360651              3366 ns/op          80.81 MB/s        4024 B/op         49 allocs/op
BenchmarkAEAD/1KiB-4              336516              3539 ns/op         293.83 MB/s        4024 B/op         49 allocs/op
BenchmarkAEAD/16KiB-4             196482              6182 ns/op        2652.91 MB/s        4024 B/op         49 allocs/op
BenchmarkAEAD/1MiB-4                5643            212594 ns/op        4932.37 MB/s        4024 B/op         49 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25,4)

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64                                                                                                                                                                                                                                        
pkg: github.com/codahale/lockstitch-go                                                                                                                                                                                                               
cpu: Apple M4 Pro                                                                                                                                                                                                                                    
BenchmarkInit-14                        36090285             33.05 ns/op                             224 B/op          1 allocs/op                                                                                                                                                   
BenchmarkMix-14                         24101325             49.22 ns/op                              48 B/op          4 allocs/op                                                                                                                                                   
BenchmarkDerive-14                       2284488             523.4 ns/op                            1696 B/op         20 allocs/op                                                                                                                                                   
BenchmarkEncrypt-14                      1340080             895.4 ns/op                            3328 B/op         29 allocs/op                                                                                                                                                   
BenchmarkDecrypt-14                      1330422             901.2 ns/op                            3328 B/op         29 allocs/op                                                                                                                                                   
BenchmarkSeal-14                         1000000              1065 ns/op                            3656 B/op         36 allocs/op                                                                                                                                                   
BenchmarkOpen-14                         1000000              1128 ns/op                            3896 B/op         38 allocs/op                                                                                                                                                   
BenchmarkHash/16B-14                     1910043             625.7 ns/op          25.57 MB/s        2000 B/op         26 allocs/op                                                                                                                                   
BenchmarkHash/256B-14                    1588180             753.9 ns/op         339.57 MB/s        2000 B/op         26 allocs/op                                                                                                                                   
BenchmarkHash/1KiB-14                     978200              1161 ns/op         881.70 MB/s        2000 B/op         26 allocs/op                                                                                                                                   
BenchmarkHash/16KiB-14                    126004              9347 ns/op        1752.83 MB/s        2000 B/op         26 allocs/op                                                                                                                                   
BenchmarkHash/1MiB-14                       2127            558598 ns/op        1877.16 MB/s        2000 B/op         26 allocs/op                                                                                                                                   
BenchmarkPRF/16B-14                      1937462             620.1 ns/op          25.80 MB/s        1968 B/op         25 allocs/op                                                                                                                                   
BenchmarkPRF/256B-14                     1879759             638.5 ns/op         400.93 MB/s        1968 B/op         25 allocs/op                                                                                                                                   
BenchmarkPRF/1KiB-14                     1730253             691.8 ns/op        1480.22 MB/s        1968 B/op         25 allocs/op                                                                                                                                   
BenchmarkPRF/16KiB-14                     647250              1871 ns/op        8759.10 MB/s        1968 B/op         25 allocs/op                                                                                                                                   
BenchmarkPRF/1MiB-14                       14668             82268 ns/op       12745.88 MB/s        1968 B/op         25 allocs/op                                                                                                                                   
BenchmarkStream/16B-14                    865290              1276 ns/op          12.54 MB/s        3648 B/op         38 allocs/op                                                                                                                                   
BenchmarkStream/256B-14                   907735              1365 ns/op         187.51 MB/s        3648 B/op         38 allocs/op                                                                                                                   
BenchmarkStream/1KiB-14                   794491              1512 ns/op         677.18 MB/s        3648 B/op         38 allocs/op                                                                                                                   
BenchmarkStream/16KiB-14                  319736              3570 ns/op        4589.06 MB/s        3648 B/op         38 allocs/op                                                                                                                   
BenchmarkStream/1MiB-14                     7684            157222 ns/op        6669.38 MB/s        3648 B/op         38 allocs/op                                                                                                                   
BenchmarkAEAD/16B-14                      812604              1421 ns/op          22.52 MB/s        4024 B/op         49 allocs/op                                                                                                                   
BenchmarkAEAD/256B-14                     808467              1549 ns/op         175.59 MB/s        4024 B/op         49 allocs/op                                                                                                                   
BenchmarkAEAD/1KiB-14                     729139              1585 ns/op         656.06 MB/s        4024 B/op         49 allocs/op                                                                                                                   
BenchmarkAEAD/16KiB-14                    312816              3702 ns/op        4430.27 MB/s        4024 B/op         49 allocs/op                                                                                                                   
BenchmarkAEAD/1MiB-14                       7447            159835 ns/op        6560.47 MB/s        4024 B/op         49 allocs/op
```
