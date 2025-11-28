# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                 19638952              56.57 ns/op                            224 B/op          1 allocs/op
BenchmarkMix-4                  11722460              103.6 ns/op                             48 B/op          4 allocs/op
BenchmarkDerive-4                1000000              1063 ns/op                            2016 B/op         14 allocs/op
BenchmarkEncrypt-4                703394              2157 ns/op                            3792 B/op         20 allocs/op
BenchmarkDecrypt-4                626644              1873 ns/op                            3792 B/op         20 allocs/op
BenchmarkSeal-4                   537562              2133 ns/op                            4256 B/op         23 allocs/op
BenchmarkOpen-4                   578768              2211 ns/op                            4480 B/op         24 allocs/op
BenchmarkHash/16B-4               954530              1227 ns/op          13.04 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/256B-4              716750              1604 ns/op         159.61 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/1KiB-4              430051              2756 ns/op         371.52 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/16KiB-4              47589             25619 ns/op         639.51 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/1MiB-4                 771           1549814 ns/op         676.58 MB/s        2320 B/op         20 allocs/op
BenchmarkPRF/16B-4                867619              1240 ns/op          12.91 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/256B-4               922822              1249 ns/op         204.92 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/1KiB-4               883885              1319 ns/op         776.56 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/16KiB-4              407050              2974 ns/op        5509.28 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/1MiB-4                 8698            128548 ns/op        8157.07 MB/s        2288 B/op         19 allocs/op
BenchmarkStream/16B-4             432655              2652 ns/op           6.03 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/256B-4            444199              2694 ns/op          95.02 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/1KiB-4            424653              2810 ns/op         364.40 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/16KiB-4           204781              5795 ns/op        2827.27 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/1MiB-4              5980            199377 ns/op        5259.27 MB/s        4112 B/op         29 allocs/op
BenchmarkAEAD/16B-4               382113              3135 ns/op          10.21 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/256B-4              371708              3194 ns/op          85.16 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/1KiB-4              349711              3382 ns/op         307.52 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/16KiB-4             200593              5865 ns/op        2796.20 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/1MiB-4                5862            200638 ns/op        5226.28 MB/s        4624 B/op         36 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25,4)

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/lockstitch-go
cpu: Apple M4 Pro
BenchmarkInit-14                        34714777              34.27 ns/op                            224 B/op          1 allocs/op
BenchmarkMix-14                         23411626              49.88 ns/op                             48 B/op          4 allocs/op
BenchmarkDerive-14                       2184512             551.0 ns/op                            2016 B/op         14 allocs/op
BenchmarkEncrypt-14                      1276638             941.4 ns/op                            3792 B/op         20 allocs/op
BenchmarkDecrypt-14                      1242858             962.2 ns/op                            3792 B/op         20 allocs/op
BenchmarkSeal-14                         1000000              1185 ns/op                            4256 B/op         23 allocs/op
BenchmarkOpen-14                         1020697              1178 ns/op                            4480 B/op         24 allocs/op
BenchmarkHash/16B-14                     1838954             654.0 ns/op          24.46 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/256B-14                    1531746             783.8 ns/op         326.62 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/1KiB-14                     990643              1186 ns/op         863.10 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/16KiB-14                    127837              9355 ns/op        1751.42 MB/s        2320 B/op         20 allocs/op
BenchmarkHash/1MiB-14                       2142            557443 ns/op        1881.05 MB/s        2320 B/op         20 allocs/op
BenchmarkPRF/16B-14                      1860934             644.6 ns/op          24.82 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/256B-14                     1828270             658.6 ns/op         388.72 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/1KiB-14                     1686453             712.0 ns/op        1438.18 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/16KiB-14                     646053              1823 ns/op        8987.84 MB/s        2288 B/op         19 allocs/op
BenchmarkPRF/1MiB-14                       15112             79238 ns/op       13233.32 MB/s        2288 B/op         19 allocs/op
BenchmarkStream/16B-14                    896082              1267 ns/op          12.62 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/256B-14                   889550              1284 ns/op         199.45 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/1KiB-14                   824612              1409 ns/op         726.77 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/16KiB-14                  324772              3631 ns/op        4511.94 MB/s        4112 B/op         29 allocs/op
BenchmarkStream/1MiB-14                     7554            156271 ns/op        6710.00 MB/s        4112 B/op         29 allocs/op
BenchmarkAEAD/16B-14                      775318              1477 ns/op          21.67 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/256B-14                     779853              1504 ns/op         180.86 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/1KiB-14                     727149              1613 ns/op         644.60 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/16KiB-14                    321553              3690 ns/op        4444.95 MB/s        4624 B/op         36 allocs/op
BenchmarkAEAD/1MiB-14                       7716            157330 ns/op        6664.91 MB/s        4624 B/op         36 allocs/op
```
