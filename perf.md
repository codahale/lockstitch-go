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

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25.4)

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64                                                                                                                                                                                                                                        
pkg: github.com/codahale/lockstitch-go                                                                                                                                                                                                               
cpu: Apple M4 Pro                                                                                                                                                                                                                                    
BenchmarkInit-14                        40266553             29.70 ns/op                             224 B/op          1 allocs/op                                                                                                                                                   
BenchmarkMix-14                         43574304             27.04 ns/op                              24 B/op          1 allocs/op                                                                                                                                                   
BenchmarkDerive-14                       2630343             456.5 ns/op                            1640 B/op         10 allocs/op                                                                                                                                                   
BenchmarkEncrypt-14                      1499149             799.2 ns/op                            3240 B/op         15 allocs/op                                                                                                                                                   
BenchmarkDecrypt-14                      1490743             804.1 ns/op                            3240 B/op         15 allocs/op                                                                                                                                                   
BenchmarkSeal-14                         1293421             928.3 ns/op                            3544 B/op         18 allocs/op                                                                                                                                                   
BenchmarkOpen-14                         1226958             979.2 ns/op                            3768 B/op         19 allocs/op                                                                                                                                                   
BenchmarkHash/16B-14                     2332371             514.7 ns/op          31.09 MB/s        1936 B/op         13 allocs/op                                                                                                                                   
BenchmarkHash/256B-14                    1845967             649.0 ns/op         394.45 MB/s        1936 B/op         13 allocs/op                                                                                                                                   
BenchmarkHash/1KiB-14                    1000000              1055 ns/op         970.52 MB/s        1936 B/op         13 allocs/op                                                                                                                                   
BenchmarkHash/16KiB-14                    127868              9184 ns/op        1783.92 MB/s        1936 B/op         13 allocs/op                                                                                                                                   
BenchmarkHash/1MiB-14                       2140            554673 ns/op        1890.44 MB/s        1936 B/op         13 allocs/op                                                                                                                                   
BenchmarkPRF/16B-14                      2361104             509.4 ns/op          31.41 MB/s        1896 B/op         12 allocs/op                                                                                                                                   
BenchmarkPRF/256B-14                     2295396             521.4 ns/op         490.99 MB/s        1896 B/op         12 allocs/op                                                                                                                                   
BenchmarkPRF/1KiB-14                     2104161             570.2 ns/op        1795.74 MB/s        1896 B/op         12 allocs/op                                                                                                                                   
BenchmarkPRF/16KiB-14                     698001              1682 ns/op        9740.15 MB/s        1896 B/op         12 allocs/op                                                                                                                                   
BenchmarkPRF/1MiB-14                       15171             78919 ns/op       13286.66 MB/s        1896 B/op         12 allocs/op                                                                                                                                   
BenchmarkStream/16B-14                   1000000              1076 ns/op          14.87 MB/s        3520 B/op         18 allocs/op                                                                                                                                   
BenchmarkStream/256B-14                  1000000              1091 ns/op         234.61 MB/s        3520 B/op         18 allocs/op                                                                                                                   
BenchmarkStream/1KiB-14                   946957              1214 ns/op         843.66 MB/s        3520 B/op         18 allocs/op                                                                                                                   
BenchmarkStream/16KiB-14                  343863              3421 ns/op        4789.29 MB/s        3520 B/op         18 allocs/op                                                                                                                   
BenchmarkStream/1MiB-14                     7666            155963 ns/op        6723.22 MB/s        3520 B/op         18 allocs/op                                                                                                                   
BenchmarkAEAD/16B-14                      950836              1211 ns/op          26.43 MB/s        3848 B/op         22 allocs/op                                                                                                                   
BenchmarkAEAD/256B-14                     935575              1255 ns/op         216.66 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/1KiB-14                     875134              1356 ns/op         766.72 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/16KiB-14                    345373              3440 ns/op        4767.33 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/1MiB-14                       7670            157074 ns/op        6675.77 MB/s        3848 B/op         22 allocs/op
```
