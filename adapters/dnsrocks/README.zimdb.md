# ZimDB authority through DNSRocks

This directory contains the qualified DNSRocks control module, derived from
Meta DNS commit `943c50fe80340760c44aeeb0d3460e527cbc5339`. Its additional master-file
import path, dependency updates and optional typed/ENT hooks are retained.
`UPSTREAM.json` records this lineage. Apache-2.0 and go-cdb MIT license texts are
included alongside the corresponding code.

Go 1.26+, RocksDB 9.11.2 headers/shared library, ldns, LZ4, Zstandard and
OpenSSL development libraries are required.

```sh
cd adapters/dnsrocks
CGO_ENABLED=1 go build -a -o ../../build/dnsrocks ./cmd/dnsrocks
../../build/dnsrocks -ip 127.0.0.1 -port 5353 \
  -dbdriver zimdb -dbpath /path/to/example.zim \
  -cache=false -watchdb=false -reloadtime 0 -cpu 1
```

Create the repository `build/` directory before the command. With a custom
RocksDB installation, set `CGO_CFLAGS=-I<prefix>/include` and
`CGO_LDFLAGS='-L<prefix>/lib -Wl,-rpath,<prefix>/lib'`.

`internal/zimnative/bridge.cc` uses the native image core and the canonical
`experiments/queryable_zone/serving_reader.inc`. The reader expands requested
owner/types, derives NS/SOA/ENT flags from metadata, and uses bounded page and
pool caches. The page LRU permits retaining one page above its target budget.
Use `go build -a` after changing headers outside this Go module so cgo recompiles
the shared native implementation.

Regression suites run with `go test ./db ./dnsserver`. The existing `testdata/`
contains public synthetic fixture records and their fixed example signing key.

The measured authority adapter has a known nested-delegation limit: when an
outer and an occluded deeper delegation both occur in the image, its authority
flow may choose the deeper referral. The native image query API correctly
reports the first cut from the zone apex. Publication smoke passed 8/9 cases;
this remaining case is recorded in the experiment report. The fixed COM
workload does not establish complete authority semantic equivalence.

Native RocksDB serving uses `-dbdriver rocksdb -dbpath <native-database>`.
COM measurements use the same authority control flow, disabled response caches,
one worker, the frozen source-derived workload and independently checked replies.
Full query measurements and remaining scope limits are documented in
`../../docs/experiments/com-20260919-20261114.md`.
