# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                  2165827             557.4 ns/op                             552 B/op          4 allocs/op
BenchmarkMix-4                  13666311             88.00 ns/op                               0 B/op          0 allocs/op
BenchmarkDerive-4                 879452              1312 ns/op                             208 B/op          1 allocs/op
BenchmarkEncrypt-4                523238              2141 ns/op                            1248 B/op          4 allocs/op
BenchmarkDecrypt-4                557797              2155 ns/op                            1248 B/op          4 allocs/op
BenchmarkSeal-4                   459835              2519 ns/op                            1232 B/op          3 allocs/op
BenchmarkOpen-4                   375285              3103 ns/op                            1800 B/op          7 allocs/op
BenchmarkHash/16B-4               594097              1983 ns/op           8.07 MB/s         808 B/op          6 allocs/op
BenchmarkHash/256B-4              503588              2327 ns/op         110.00 MB/s         808 B/op          6 allocs/op
BenchmarkHash/1KiB-4              297462              4003 ns/op         255.78 MB/s         808 B/op          6 allocs/op
BenchmarkHash/16KiB-4              34905             34360 ns/op         476.83 MB/s         808 B/op          6 allocs/op
BenchmarkHash/1MiB-4                 579           2050418 ns/op         511.40 MB/s         808 B/op          6 allocs/op
BenchmarkPRF/16B-4                574412              1949 ns/op           8.21 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/256B-4               517459              2287 ns/op         111.95 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/1KiB-4               294304              3963 ns/op         258.40 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/16KiB-4               35305             33876 ns/op         483.64 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/1MiB-4                  579           2058724 ns/op         509.33 MB/s         760 B/op          5 allocs/op
BenchmarkStream/16B-4             396388              2829 ns/op           5.66 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/256B-4            405544              2877 ns/op          89.00 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/1KiB-4            399728              3053 ns/op         335.44 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/16KiB-4           196976              6033 ns/op        2715.84 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/1MiB-4              5871            203889 ns/op        5142.87 MB/s        1816 B/op          8 allocs/op
BenchmarkAEAD/16B-4               351687              3291 ns/op           9.72 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/256B-4              355010              3335 ns/op          81.57 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/1KiB-4              345812              3473 ns/op         299.41 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/16KiB-4             183427              6459 ns/op        2539.25 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/1MiB-4                5782            205741 ns/op        5096.67 MB/s        1800 B/op          7 allocs/op
```

## `arm64` (Apple MacBook Pro `Mac16,7` M4 Pro, macOS 26.1, Go 1.25,4)

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/lockstitch-go
cpu: Apple M4 Pro
BenchmarkInit-14                         4764178             233.4 ns/op                             552 B/op          4 allocs/op
BenchmarkMix-14                         27569727             42.70 ns/op                               0 B/op          0 allocs/op
BenchmarkDerive-14                       2477716             494.2 ns/op                             208 B/op          1 allocs/op
BenchmarkEncrypt-14                      1395549             872.1 ns/op                            1248 B/op          4 allocs/op
BenchmarkDecrypt-14                      1384447             868.7 ns/op                            1248 B/op          4 allocs/op
BenchmarkSeal-14                         1000000              1044 ns/op                            1232 B/op          3 allocs/op
BenchmarkOpen-14                          872602              1303 ns/op                            1800 B/op          7 allocs/op
BenchmarkHash/16B-14                     1559390             767.1 ns/op          20.86 MB/s         808 B/op          6 allocs/op
BenchmarkHash/256B-14                    1365642             884.2 ns/op         289.54 MB/s         808 B/op          6 allocs/op
BenchmarkHash/1KiB-14                     772122              1498 ns/op         683.55 MB/s         808 B/op          6 allocs/op
BenchmarkHash/16KiB-14                     95606             12776 ns/op        1282.39 MB/s         808 B/op          6 allocs/op
BenchmarkHash/1MiB-14                       1544            753003 ns/op        1392.53 MB/s         808 B/op          6 allocs/op
BenchmarkPRF/16B-14                      1590676             759.0 ns/op          21.08 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/256B-14                     1362560             881.3 ns/op         290.49 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/1KiB-14                      797516              1463 ns/op         699.71 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/16KiB-14                      98514             12144 ns/op        1349.09 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/1MiB-14                        1633            728393 ns/op        1439.58 MB/s         760 B/op          5 allocs/op
BenchmarkStream/16B-14                    973837              1172 ns/op          13.65 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/256B-14                   924900              1199 ns/op         213.43 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/1KiB-14                   838346              1298 ns/op         788.93 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/16KiB-14                  383931              3071 ns/op        5335.36 MB/s        1816 B/op          8 allocs/op
BenchmarkStream/1MiB-14                     9421            125507 ns/op        8354.72 MB/s        1816 B/op          8 allocs/op
BenchmarkAEAD/16B-14                      848793              1355 ns/op          23.61 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/256B-14                     830184              1391 ns/op         195.55 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/1KiB-14                     788347              1475 ns/op         704.85 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/16KiB-14                    350078              3259 ns/op        5032.65 MB/s        1800 B/op          7 allocs/op
BenchmarkAEAD/1MiB-14                       9331            126538 ns/op        8286.75 MB/s        1800 B/op          7 allocs/op
```
