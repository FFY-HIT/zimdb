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

The next isolated P2 iteration replaces the per-page owner-to-ordinal balanced
tree with a sorted vector of non-owning unique-owner views. Preparing that
index takes O(N), rather than O(N log G); only NSEC3 next-owner lookups perform
binary search. Views refer to the immutable page input and use unsigned byte
comparison. Missing next owners retain the literal fallback. The format and
ordinals are unchanged. `ZIMDB_OWNER_RANK_VECTOR=0` retains the tree ablation.
On the one-trial 10,000-page screen, encoder-only time changed from 5.14422 s
to 4.33856 s, with identical component bytes and SHA256. This is a component
screen, not whole-build time; it does not estimate variance. Source-derived
multiset, case, semantics and update regressions passed independently.

An implementation control adds literal-message overloads for `require` and
`syscheck`. Successful checks no longer construct temporary diagnostic strings;
all checks and failure exception types/text remain. Dynamic messages retain
their old overloads. This is implementation overhead removal, not algorithmic
novelty. `ZIMDB_LAZY_CHECK_TEXT=0` retains the former path for ablation. The
single isolated 10,000-page screen is retained with source/input before/after
hashes and probe binary hashes captured after execution. Output and check-failure
behavior match. Whole-build benefit needs a separate same-protocol cloud case.

`--encode-workers 2` enables a bounded page pipeline once both tagged dictionary
quotas close. Admission remains sequential. A closed dictionary is probed through
const lookups; independent page encoding runs in fixed workers and extents/COW
index entries are committed in original order. At most workers+1 jobs are in
flight, and a dictionary that never closes retains sequential construction.
The configured worker count bounds added page workspaces; total process RSS is
still measured rather than asserted equal to the configured memory limit.
Worker1 is the serial ablation. Independent regressions cover caps0/64/65536,
workers1/2/4, unknown/non-20-byte DNSSEC, duplicates, shuffled input, never-closing
dictionary fallback, worker exception propagation and generation updates.
