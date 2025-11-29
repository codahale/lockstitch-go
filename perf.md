# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 21502348              55.33 ns/op                            224 B/op          1 allocs/op
BenchmarkMix-4                  19587075              62.02 ns/op                             24 B/op          1 allocs/op
BenchmarkDerive-4                1000000              1051 ns/op                            1672 B/op         10 allocs/op
BenchmarkEncrypt-4                679722              1807 ns/op                            3288 B/op         15 allocs/op
BenchmarkDecrypt-4                657135              1798 ns/op                            3288 B/op         15 allocs/op
BenchmarkSeal-4                   547948              2178 ns/op                            3608 B/op         18 allocs/op
BenchmarkOpen-4                   512757              2230 ns/op                            3832 B/op         19 allocs/op
BenchmarkHash/16B-4               870489              1190 ns/op          13.45 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/256B-4              732348              1640 ns/op         156.11 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/1KiB-4              399898              2934 ns/op         348.99 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/16KiB-4              41678             28751 ns/op         569.86 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/1MiB-4                 674           1767959 ns/op         593.10 MB/s        1968 B/op         13 allocs/op
BenchmarkPRF/16B-4                915912              1184 ns/op          13.52 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/256B-4               933512              1213 ns/op         210.97 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/1KiB-4               891565              1339 ns/op         764.97 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/16KiB-4              309235              3859 ns/op        4245.62 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/1MiB-4                 6285            188291 ns/op        5568.90 MB/s        1928 B/op         12 allocs/op
BenchmarkStream/16B-4             417655              2628 ns/op           6.09 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/256B-4            448898              2686 ns/op          95.32 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/1KiB-4            410734              2872 ns/op         356.53 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/16KiB-4           175569              6728 ns/op        2435.08 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/1MiB-4              4508            263974 ns/op        3972.28 MB/s        3568 B/op         18 allocs/op
BenchmarkAEAD/16B-4               368877              3095 ns/op          10.34 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/256B-4              375854              3137 ns/op          86.72 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/1KiB-4              354541              3324 ns/op         312.85 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/16KiB-4             178558              6695 ns/op        2449.69 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/1MiB-4                4534            264062 ns/op        3971.00 MB/s        3912 B/op         22 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25.4)

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/lockstitch-go
cpu: Apple M4 Pro
BenchmarkInit-14                        33452002             29.93 ns/op                             224 B/op          1 allocs/op
BenchmarkMix-14                         42341670             27.32 ns/op                              24 B/op          1 allocs/op
BenchmarkDerive-14                       2393503             495.6 ns/op                            1672 B/op         10 allocs/op
BenchmarkEncrypt-14                      1411083             850.1 ns/op                            3288 B/op         15 allocs/op
BenchmarkDecrypt-14                      1397654             878.2 ns/op                            3288 B/op         15 allocs/op
BenchmarkSeal-14                         1000000              1030 ns/op                            3608 B/op         18 allocs/op
BenchmarkOpen-14                         1000000              1049 ns/op                            3832 B/op         19 allocs/op
BenchmarkHash/16B-14                     2219718             541.0 ns/op          29.57 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/256B-14                    1781438             674.7 ns/op         379.42 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/1KiB-14                    1000000              1077 ns/op         950.89 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/16KiB-14                    126750              9257 ns/op        1769.82 MB/s        1968 B/op         13 allocs/op
BenchmarkHash/1MiB-14                       2098            559431 ns/op        1874.36 MB/s        1968 B/op         13 allocs/op
BenchmarkPRF/16B-14                      2279863             526.9 ns/op          30.37 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/256B-14                     2208333             542.8 ns/op         471.64 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/1KiB-14                     1951503             615.8 ns/op        1662.95 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/16KiB-14                     583214              2017 ns/op        8121.06 MB/s        1928 B/op         12 allocs/op
BenchmarkPRF/1MiB-14                       12607             95485 ns/op       10981.60 MB/s        1928 B/op         12 allocs/op
BenchmarkStream/16B-14                   1000000              1112 ns/op          14.38 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/256B-14                   972979              1155 ns/op         221.73 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/1KiB-14                   870518              1301 ns/op         787.39 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/16KiB-14                  309212              3824 ns/op        4284.20 MB/s        3568 B/op         18 allocs/op
BenchmarkStream/1MiB-14                     6727            172931 ns/op        6063.55 MB/s        3568 B/op         18 allocs/op
BenchmarkAEAD/16B-14                      885829              1263 ns/op          25.34 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/256B-14                     843362              1303 ns/op         208.73 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/1KiB-14                     788684              1423 ns/op         730.75 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/16KiB-14                    307597              3794 ns/op        4322.52 MB/s        3912 B/op         22 allocs/op
BenchmarkAEAD/1MiB-14                       6775            172849 ns/op        6066.53 MB/s        3912 B/op         22 allocs/op
```
