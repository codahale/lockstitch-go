# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 22288899             52.64 ns/op                             224 B/op          1 allocs/op
BenchmarkMix-4                  20775681             58.10 ns/op                              24 B/op          1 allocs/op
BenchmarkDerive-4                1219137             984.8 ns/op                            1640 B/op         10 allocs/op
BenchmarkEncrypt-4                727088              1652 ns/op                            3240 B/op         15 allocs/op
BenchmarkDecrypt-4                733578              1656 ns/op                            3240 B/op         15 allocs/op
BenchmarkSeal-4                   566029              1996 ns/op                            3544 B/op         18 allocs/op
BenchmarkOpen-4                   584718              2060 ns/op                            3768 B/op         19 allocs/op
BenchmarkHash/16B-4               994383              1102 ns/op          14.51 MB/s        1936 B/op         13 allocs/op
BenchmarkHash/256B-4              746062              1532 ns/op         167.06 MB/s        1936 B/op         13 allocs/op
BenchmarkHash/1KiB-4              420618              2764 ns/op         370.44 MB/s        1936 B/op         13 allocs/op
BenchmarkHash/16KiB-4              43454             27597 ns/op         593.70 MB/s        1936 B/op         13 allocs/op
BenchmarkHash/1MiB-4                 709           1698180 ns/op         617.47 MB/s        1936 B/op         13 allocs/op
BenchmarkPRF/16B-4               1000000              1089 ns/op          14.69 MB/s        1896 B/op         12 allocs/op
BenchmarkPRF/256B-4              1000000              1108 ns/op         231.14 MB/s        1896 B/op         12 allocs/op
BenchmarkPRF/1KiB-4               999666              1199 ns/op         854.33 MB/s        1896 B/op         12 allocs/op
BenchmarkPRF/16KiB-4              400438              3035 ns/op        5398.48 MB/s        1896 B/op         12 allocs/op
BenchmarkPRF/1MiB-4                 8196            140536 ns/op        7461.28 MB/s        1896 B/op         12 allocs/op
BenchmarkStream/16B-4             465272              2409 ns/op           6.64 MB/s        3520 B/op         18 allocs/op
BenchmarkStream/256B-4            481228              2449 ns/op         104.54 MB/s        3520 B/op         18 allocs/op
BenchmarkStream/1KiB-4            461575              2621 ns/op         390.66 MB/s        3520 B/op         18 allocs/op
BenchmarkStream/16KiB-4           207934              5712 ns/op        2868.41 MB/s        3520 B/op         18 allocs/op
BenchmarkStream/1MiB-4              5643            212718 ns/op        4929.42 MB/s        3520 B/op         18 allocs/op
BenchmarkAEAD/16B-4               394693              2856 ns/op          11.21 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/256B-4              411949              2880 ns/op          94.43 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/1KiB-4              390028              3047 ns/op         341.35 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/16KiB-4             207296              5721 ns/op        2866.77 MB/s        3848 B/op         22 allocs/op
BenchmarkAEAD/1MiB-4                5631            211331 ns/op        4961.85 MB/s        3848 B/op         22 allocs/op
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
