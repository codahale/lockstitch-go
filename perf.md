# Performance

## `amd64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, Go 1.25.4)

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/lockstitch-go
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkInit-4                  2029417             590.8 ns/op                             552 B/op          4 allocs/op
BenchmarkMix-4                  13269042             91.31 ns/op                               0 B/op          0 allocs/op
BenchmarkDerive-4                 843426              1369 ns/op                             208 B/op          1 allocs/op
BenchmarkEncrypt-4                631332              1902 ns/op                            2048 B/op          5 allocs/op
BenchmarkDecrypt-4                623270              1886 ns/op                            2048 B/op          5 allocs/op
BenchmarkSeal-4                   527664              2306 ns/op                            2048 B/op          5 allocs/op
BenchmarkOpen-4                   410666              2905 ns/op                            2616 B/op          9 allocs/op
BenchmarkHash/16B-4               546706              2064 ns/op           7.75 MB/s         808 B/op          6 allocs/op
BenchmarkHash/256B-4              484450              2417 ns/op         105.93 MB/s         808 B/op          6 allocs/op
BenchmarkHash/1KiB-4              283995              4167 ns/op         245.72 MB/s         808 B/op          6 allocs/op
BenchmarkHash/16KiB-4              33438             35783 ns/op         457.88 MB/s         808 B/op          6 allocs/op
BenchmarkHash/1MiB-4                 562           2133191 ns/op         491.55 MB/s         808 B/op          6 allocs/op
BenchmarkPRF/16B-4                542724              2033 ns/op           7.87 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/256B-4               480939              2399 ns/op         106.72 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/1KiB-4               284300              4118 ns/op         248.64 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/16KiB-4               34090             35265 ns/op         464.59 MB/s         760 B/op          5 allocs/op
BenchmarkPRF/1MiB-4                  560           2148355 ns/op         488.08 MB/s         760 B/op          5 allocs/op
BenchmarkStream/16B-4             433038              2618 ns/op           6.11 MB/s        2616 B/op          9 allocs/op
BenchmarkStream/256B-4            444368              2671 ns/op          95.83 MB/s        2616 B/op          9 allocs/op
BenchmarkStream/1KiB-4            415550              2844 ns/op         360.09 MB/s        2616 B/op          9 allocs/op
BenchmarkStream/16KiB-4           194714              6039 ns/op        2712.84 MB/s        2616 B/op          9 allocs/op
BenchmarkStream/1MiB-4              5331            219635 ns/op        4774.18 MB/s        2616 B/op          9 allocs/op
BenchmarkAEAD/16B-4               357840              3113 ns/op          10.28 MB/s        2616 B/op          9 allocs/op
BenchmarkAEAD/256B-4              370528              3153 ns/op          86.25 MB/s        2616 B/op          9 allocs/op
BenchmarkAEAD/1KiB-4              356997              3338 ns/op         311.58 MB/s        2616 B/op          9 allocs/op
BenchmarkAEAD/16KiB-4             183391              6612 ns/op        2480.37 MB/s        2616 B/op          9 allocs/op
BenchmarkAEAD/1MiB-4                5330            220509 ns/op        4755.31 MB/s        2616 B/op          9 allocs/op
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
