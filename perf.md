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
BenchmarkInit-14                     4775397         230.9 ns/op                         552 B/op           4 allocs/op
BenchmarkMix-14                     28030778         43.05 ns/op                           0 B/op           0 allocs/op
BenchmarkDerive-14                   2500192         479.4 ns/op                         208 B/op           1 allocs/op
BenchmarkEncrypt-14                  1561074         767.3 ns/op                        2048 B/op           5 allocs/op
BenchmarkDecrypt-14                  1543304         777.7 ns/op                        2048 B/op           5 allocs/op
BenchmarkSeal-14                     1318500         910.6 ns/op                        2048 B/op           5 allocs/op
BenchmarkOpen-14                     1000000          1166 ns/op                        2616 B/op           9 allocs/op
BenchmarkHash/16B-14                 1577232         760.1 ns/op      21.05 MB/s         808 B/op           6 allocs/op
BenchmarkHash/256B-14                1370876         874.7 ns/op     292.66 MB/s         808 B/op           6 allocs/op
BenchmarkHash/1KiB-14                 813522          1472 ns/op     695.50 MB/s         808 B/op           6 allocs/op
BenchmarkHash/16KiB-14                 96498         12332 ns/op    1328.61 MB/s         808 B/op           6 allocs/op
BenchmarkHash/1MiB-14                   1606        741758 ns/op    1413.64 MB/s         808 B/op           6 allocs/op
BenchmarkPRF/16B-14                  1597029         751.3 ns/op      21.30 MB/s         760 B/op           5 allocs/op
BenchmarkPRF/256B-14                 1381951         867.1 ns/op     295.24 MB/s         760 B/op           5 allocs/op
BenchmarkPRF/1KiB-14                  834523          1445 ns/op     708.48 MB/s         760 B/op           5 allocs/op
BenchmarkPRF/16KiB-14                  99217         12032 ns/op    1361.67 MB/s         760 B/op           5 allocs/op
BenchmarkPRF/1MiB-14                    1647        723322 ns/op    1449.67 MB/s         760 B/op           5 allocs/op
BenchmarkStream/16B-14               1000000          1071 ns/op      14.94 MB/s        2616 B/op           9 allocs/op
BenchmarkStream/256B-14              1000000          1108 ns/op     231.01 MB/s        2616 B/op           9 allocs/op
BenchmarkStream/1KiB-14               989149          1215 ns/op     842.90 MB/s        2616 B/op           9 allocs/op
BenchmarkStream/16KiB-14              351892          3427 ns/op    4781.24 MB/s        2616 B/op           9 allocs/op
BenchmarkStream/1MiB-14                 7878        153112 ns/op    6848.43 MB/s        2616 B/op           9 allocs/op
BenchmarkAEAD/16B-14                  900528          1263 ns/op      25.33 MB/s        2616 B/op           9 allocs/op
BenchmarkAEAD/256B-14                 920176          1283 ns/op     211.92 MB/s        2616 B/op           9 allocs/op
BenchmarkAEAD/1KiB-14                 866902          1393 ns/op     746.40 MB/s        2616 B/op           9 allocs/op
BenchmarkAEAD/16KiB-14                334064          3596 ns/op    4561.07 MB/s        2616 B/op           9 allocs/op
BenchmarkAEAD/1MiB-14                   7875        154752 ns/op    6775.95 MB/s        2616 B/op           9 allocs/op
```
