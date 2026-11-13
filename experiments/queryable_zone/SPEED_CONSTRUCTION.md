# Bounded construction speed iteration

The optional `--input-syntax simd` path streams simdzone canonical RR events into
the same owner-order verifier and bounded primary/exception sorter. Build with
`make SIMDZONE_DIR=/path/to/simdzone`. The dependency must be built first with
CMake Release, pinned to `c593a299b6d37450f0640fafdf336825e42ffc61` for the cloud
experiment. It uses a 16 KiB source window and bounded parser/name/RDATA scratch;
it never collects the entire zone. Includes are disabled. Duplicate SOAs are
retained. Unsupported canonical layouts use ldns wire canonicalization, rather
than omitting the record. Parser failures do not publish an image.

Known COM layouts are canonicalized directly: owner names, NS targets, both SOA
names and RRSIG signer names are lowercased as DNS names. Opaque RDATA remains
byte-exact. The independent RR multiset and semantic qualifications include
unknown types, non-20-byte NSEC3, large TXT, duplicates, ENT, wildcard and cuts.

The page encoder factors owner-relative NS context once per owner group and
materializes keyless payload definitions. This replaces repeated owner-name
decoding per NS RR with one group operation. The on-disk representation is
unchanged. `ZIMDB_GROUP_NS_CONTEXT=0` retains the previous path for ablation.

A fingerprint index with exact byte collision resolution was also tested.
On the fixed 30,000-page screen it made the context optimization slower
(15.0722 s versus 14.6435 s), so `ZIMDB_VIEW_INTERN` defaults to 0. The rejected
alternative remains available for reproducibility and forced-collision checks.
The selected context path took 14.6435 s versus the old 16.2554 s; these exclude
input-image decoding and are **not whole-build time or construction RSS**.

The parser primitive comes from Koekkoek and Lemire, "Parsing Millions of DNS
Records per Second", https://arxiv.org/abs/2411.12035. Reusing that primitive is
not a new parsing algorithm or an adapter contribution. Full source-to-durable
image time and RSS must be measured separately, under frozen source and code.
