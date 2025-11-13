# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 18236896             67.42 ns/op                              40 B/op          2 allocs/op
kBenchmarkMix-4                 28211306             42.65 ns/op                               0 B/op          0 allocs/op
BenchmarkDerive-4                1671836             712.9 ns/op                               0 B/op          0 allocs/op
BenchmarkEncrypt-4                796130              1411 ns/op                            1088 B/op          3 allocs/op
BenchmarkDecrypt-4                857202              1430 ns/op                            1088 B/op          3 allocs/op
BenchmarkSeal-4                   731986              1740 ns/op                            1024 B/op          2 allocs/op
BenchmarkOpen-4                   553444              1909 ns/op                            1064 B/op          4 allocs/op
BenchmarkHash/16B-4              1363550             868.9 ns/op          18.41 MB/s          56 B/op          2 allocs/op
BenchmarkHash/256B-4             1284543             932.5 ns/op         274.52 MB/s          56 B/op          2 allocs/op
BenchmarkHash/1KiB-4              653845              1810 ns/op         565.77 MB/s          56 B/op          2 allocs/op
BenchmarkHash/16KiB-4              35170             34554 ns/op         474.15 MB/s       98360 B/op          5 allocs/op
BenchmarkHash/1MiB-4                1880            665625 ns/op        1575.32 MB/s       98360 B/op          5 allocs/op
BenchmarkPRF/16B-4               1407378             846.0 ns/op          18.91 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/256B-4              1000000              1049 ns/op         244.02 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/1KiB-4               601023              1843 ns/op         555.66 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/16KiB-4               74456             16239 ns/op        1008.95 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/1MiB-4                 1196           1010565 ns/op        1037.61 MB/s          24 B/op          1 allocs/op
BenchmarkStream/16B-4             718314              1487 ns/op          10.76 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/256B-4            785841              1541 ns/op         166.16 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/1KiB-4            752530              1703 ns/op         601.23 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/16KiB-4           279750              4359 ns/op        3758.40 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/1MiB-4              6708            185449 ns/op        5654.26 MB/s        1112 B/op          4 allocs/op
BenchmarkAEAD/16B-4               472008              2327 ns/op          13.75 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/256B-4              514924              2290 ns/op         118.76 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/1KiB-4              495906              2445 ns/op         425.37 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/16KiB-4             222387              5104 ns/op        3212.94 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/1MiB-4                5898            183736 ns/op        5707.06 MB/s        1048 B/op          3 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25,4)

```text
goos: darwin
goarch: arm64
pkg: github.com/codahale/lockstitch-go
cpu: Apple M4 Pro
BenchmarkInit-14                        21773214             54.45 ns/op                              40 B/op          2 allocs/op
BenchmarkMix-14                         44373364             25.29 ns/op                               0 B/op          0 allocs/op
BenchmarkDerive-14                       2542819             466.1 ns/op                               0 B/op          0 allocs/op
BenchmarkEncrypt-14                      1326536             903.8 ns/op                            1088 B/op          3 allocs/op
BenchmarkDecrypt-14                      1344568             891.9 ns/op                            1088 B/op          3 allocs/op
BenchmarkSeal-14                         1000000              1103 ns/op                            1024 B/op          2 allocs/op
BenchmarkOpen-14                          989258              1225 ns/op                            1064 B/op          4 allocs/op
BenchmarkHash/16B-14                     2156268             554.5 ns/op          28.85 MB/s          56 B/op          2 allocs/op
BenchmarkHash/256B-14                    1881498             637.5 ns/op         401.55 MB/s          56 B/op          2 allocs/op
BenchmarkHash/1KiB-14                     939432              1233 ns/op         830.81 MB/s          56 B/op          2 allocs/op
BenchmarkHash/16KiB-14                     59565             19934 ns/op         821.93 MB/s       49208 B/op          5 allocs/op
BenchmarkHash/1MiB-14                       5101            230911 ns/op        4541.04 MB/s       49208 B/op          5 allocs/op
BenchmarkPRF/16B-14                      2225454             538.3 ns/op          29.72 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/256B-14                     1846458             650.7 ns/op         393.42 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/1KiB-14                      991215              1205 ns/op         849.61 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/16KiB-14                     108258             11123 ns/op        1472.98 MB/s          24 B/op          1 allocs/op
BenchmarkPRF/1MiB-14                        1734            688102 ns/op        1523.87 MB/s          24 B/op          1 allocs/op
BenchmarkStream/16B-14                   1215308             983.8 ns/op          16.26 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/256B-14                  1000000              1003 ns/op         255.19 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/1KiB-14                  1000000              1095 ns/op         934.97 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/16KiB-14                  400563              2883 ns/op        5682.62 MB/s        1112 B/op          4 allocs/op
BenchmarkStream/1MiB-14                     9552            123684 ns/op        8477.85 MB/s        1112 B/op          4 allocs/op
BenchmarkAEAD/16B-14                      802926              1466 ns/op          21.83 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/256B-14                     783519              1496 ns/op         181.87 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/1KiB-14                     733905              1592 ns/op         653.22 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/16KiB-14                    347097              3383 ns/op        4848.16 MB/s        1048 B/op          3 allocs/op
BenchmarkAEAD/1MiB-14                       9472            125945 ns/op        8325.78 MB/s        1048 B/op          3 allocs/op
```
