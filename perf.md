# Performance

## `amd64` (GCP `c4-highcpu-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 16436234             74.18 ns/op                              40 B/op          2 allocs/op
BenchmarkMix-4                  25772430             48.20 ns/op                               0 B/op          0 allocs/op
BenchmarkDerive-4                1575103             757.4 ns/op                               0 B/op          0 allocs/op
BenchmarkEncrypt-4               1000000              1061 ns/op                            1072 B/op          3 allocs/op
BenchmarkDecrypt-4               1000000              1041 ns/op                            1072 B/op          3 allocs/op
BenchmarkSeal-4                   905809              1335 ns/op                            1024 B/op          2 allocs/op
BenchmarkOpen-4                   790770              1508 ns/op                            1064 B/op          4 allocs/op
BenchmarkHash/16B-4              1281050             940.6 ns/op          17.01 MB/s          56 B/op          2 allocs/op
BenchmarkHash/256B-4             1000000              1025 ns/op         249.86 MB/s          56 B/op          2 allocs/op
BenchmarkHash/1KiB-4              605011              1969 ns/op         520.00 MB/s          56 B/op          2 allocs/op
BenchmarkHash/16KiB-4              32223             37269 ns/op         439.62 MB/s       98360 B/op          5 allocs/op
BenchmarkHash/1MiB-4                1693            723622 ns/op        1449.07 MB/s       98360 B/op          5 allocs/op
BenchmarkPRF/16B-4               1377500             871.3 ns/op          18.36 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/256B-4              1000000              1052 ns/op         243.28 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/1KiB-4               616177              1882 ns/op         544.21 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/16KiB-4               70160             17297 ns/op         947.23 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/1MiB-4                 1118           1067252 ns/op         982.50 MB/s          24 B/op          1 allocs/op
BenchmarkStream/16B-4             900343              1163 ns/op          13.76 MB/s        1096 B/op          4 allocs/op
BenchmarkStream/256B-4            705640              1591 ns/op         160.95 MB/s        1096 B/op          4 allocs/op
BenchmarkStream/1KiB-4            485647              2373 ns/op         431.47 MB/s        1096 B/op          4 allocs/op
BenchmarkStream/16KiB-4            44528             26644 ns/op         614.93 MB/s       66632 B/op          6 allocs/op
BenchmarkStream/1MiB-4              1527            802240 ns/op        1307.06 MB/s       66632 B/op          6 allocs/op
BenchmarkAEAD/16B-4               571228              2040 ns/op          15.69 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/256B-4              625093              1972 ns/op         137.93 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/1KiB-4              349651              3206 ns/op         324.44 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/16KiB-4              30080             39667 ns/op         413.44 MB/s       99352 B/op          6 allocs/op
BenchmarkAEAD/1MiB-4                1452            865504 ns/op        1211.54 MB/s       99352 B/op          6 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25,4)

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64                                                                                                                                                                                                                                        
pkg: github.com/codahale/lockstitch-go                                                                                                                                                                                                               
cpu: Apple M4 Pro                                                                                                                                                                                                                                    
BenchmarkInit-14                        21789001             54.49 ns/op                              40 B/op          2 allocs/op                                                                                                                                                   
BenchmarkMix-14                         46149186             24.91 ns/op                               0 B/op          0 allocs/op                                                                                                                                                   
BenchmarkDerive-14                       2605101             461.4 ns/op                               0 B/op          0 allocs/op                                                                                                                                                   
BenchmarkEncrypt-14                      1951214             612.5 ns/op                            1072 B/op          3 allocs/op                                                                                                                                                   
BenchmarkDecrypt-14                      1968522             610.6 ns/op                            1072 B/op          3 allocs/op                                                                                                                                                   
BenchmarkSeal-14                         1428846             851.2 ns/op                            1024 B/op          2 allocs/op                                                                                                                                                   
BenchmarkOpen-14                         1292317             935.7 ns/op                            1064 B/op          4 allocs/op                                                                                                                                                   
BenchmarkHash/16B-14                     2052022             576.8 ns/op          27.74 MB/s          56 B/op          2 allocs/op                                                                                                                                   
BenchmarkHash/256B-14                    1832782             663.8 ns/op         385.67 MB/s          56 B/op          2 allocs/op                                                                                                                                   
BenchmarkHash/1KiB-14                     958070              1245 ns/op         822.52 MB/s          56 B/op          2 allocs/op                                                                                                                                   
BenchmarkHash/16KiB-14                     60180             20262 ns/op         808.60 MB/s       49208 B/op          5 allocs/op                                                                                                                                   
BenchmarkHash/1MiB-14                       5110            236621 ns/op        4431.45 MB/s       49208 B/op          5 allocs/op                                                                                                                                   
BenchmarkPRF/16B-14                      2134442             555.3 ns/op          28.81 MB/s          24 B/op          1 allocs/op                                                                                                                                   
BenchmarkPRF/256B-14                     1842481             652.3 ns/op         392.46 MB/s          24 B/op          1 allocs/op                                                                                                                                   
BenchmarkPRF/1KiB-14                      995347              1246 ns/op         822.15 MB/s          24 B/op          1 allocs/op                                                                                                                                   
BenchmarkPRF/16KiB-14                     104713             11520 ns/op        1422.25 MB/s          24 B/op          1 allocs/op                                                                                                                                   
BenchmarkPRF/1MiB-14                        1738            713063 ns/op        1470.52 MB/s          24 B/op          1 allocs/op                                                                                                                                   
BenchmarkStream/16B-14                   1605544             749.2 ns/op          21.36 MB/s        1096 B/op          4 allocs/op                                                                                                                                   
BenchmarkStream/256B-14                  1219921             981.3 ns/op         260.89 MB/s        1096 B/op          4 allocs/op                                                                                                                   
BenchmarkStream/1KiB-14                   799382              1521 ns/op         673.45 MB/s        1096 B/op          4 allocs/op
BenchmarkStream/16KiB-14                   78758             15705 ns/op        1043.26 MB/s       33864 B/op          6 allocs/op
BenchmarkStream/1MiB-14                     3859            300056 ns/op        3494.60 MB/s       33864 B/op          6 allocs/op
BenchmarkAEAD/16B-14                      984907              1256 ns/op          25.47 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/256B-14                     955036              1201 ns/op         226.56 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/1KiB-14                     588542              1974 ns/op         526.76 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/16KiB-14                     55228             22122 ns/op         741.33 MB/s       50200 B/op          6 allocs/op
BenchmarkAEAD/1MiB-14                       3855            305614 ns/op        3431.10 MB/s       50200 B/op          6 allocs/op
```
