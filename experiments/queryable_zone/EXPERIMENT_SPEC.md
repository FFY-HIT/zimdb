# Queryable Compact Zone Representation

The input is the canonical RR multiset Z. The image preserves per-record TTL, arbitrary RR type wire payloads, DNSSEC, and multiplicity. Queries include explicit names, empty nonterminals, absent names, closest encloser, wildcard source, zone cuts, origin, lookup, and RRsets without reconstructing an explicit name tree.

The public base is 9635294a7a1bb3ff464c721cbd919cdb4a67d64b. This isolated worktree starts at its qualified descendant 14fedd05baf6c7cdd6ca978791e1fd104e046eb2. Earlier user modifications and measurements remain available in their original paths.

P1 measures complete image bytes. P2 measures zone text to durable image time under the declared memory/order model and sampled process-tree peak RSS. P3 measures rewritten physical bytes and reencoded owners for atomic generation updates. Each round reports the four fields separately in STAGE and SUMMARY JSON.

Agency is the first real input. Each performance configuration runs once, with CPU6/7, observerCPU4, prewarmed input, fresh output/work paths, WSL ext4 scratch, and final file/directory fsync. Runs are sequential. DNSRocks native compressed storage and native incremental updates remain strong controls.

First implement the P2 end-to-end native bounded page path and semantic acceptance. Then measure the largest remaining bottleneck and make one algorithm change per round. A dimension passes only on observed values and required semantic checks. The user thresholds remain 10x RSS reduction, build scaling comparable to the same-boundary RocksDB load, >5x native size reduction, and dirty-interval-dependent rewrite work.
