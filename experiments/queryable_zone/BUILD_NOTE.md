# Build Note

| Rung | Implementation | Acceptance | Status |
|---|---|---|---|
| F0 | Native source-to-image and tree-free lookup spine | validate.py --run-fixture with the archived binary | implemented, checks passed |
| F1 | Exact RR multiset and full name semantics | validate.py source/image/oracle qualification, plus semantic fixtures | agency G1 and generic semantics passed for qualified versions |
| F2 | Fixed-budget P2 performance | run_round.py --round FRESH --cases native_cow_zstd dnsrocks_control_zstd64k | measured; same-Z DNSRocks comparison passed, strict old-path threshold unverified |
| F3 | P1 pool/front-code/block-compression experiment | five r04 ablations and independent G1 | measured, 5x size target unmet; additional key-transform experiment pending |
| F4 | Atomic dirty-interval generation update | validate_updates.py against three delta sizes and retained roots | r06/r09 and full-reencode controls passed; ordered-input r11 only small is qualified |

## Run record

The worktree begins at 14fedd05baf6c7cdd6ca978791e1fd104e046eb2. ldns1.8.4 development headers were installed in WSL for the generic canonical RR parser.

All results and qualification receipts are under /home/administrator/zimdb_queryable_20261113. Builds use complete agency source, one trial per configuration, affinity6/7 and a separate observer on4, ext4 outputs, source pre-read by SHA256 and durable-complete fsync accounting. Update times and RSS are separate from the original build tuple.

| Round | Recorded check and outcome |
|---|---|
| r00_controls | Old source-materialized path unique-set G1 passed and multiset G1 failed by one duplicate SOA. DNSRocks full G1 passed. Old-path ratios are diagnostic only |
| r01_bounded_construct | Generic semantic defect was fixed before final fixture qualification. Agency G1 passed. RSS36,124KiB missed the workspace goal |
| r02_bounded_merge | Smaller GNU arena/fan-in produced a byte-identical image at18,748KiB, with slower4.760s build |
| r03_binary_runs | Fixed native binary arena/run generation produced the same image at11,736KiB and2.030s |
| r04_pool_representation | Five native deletion ablations and two compressed DNSRocks controls all passed full G1. Local pooling increased the Zstd image, so the primary path uses no local pool |
| r05_packed_directory | Packed directory reduced size by535,948B, all G1 and corrupt-index rejection checks passed |
| r06_generation_updates | Small/medium/whole native and native DNSRocks updates passed full G1 and old-root checks |
| r07_full_reencode_controls | Updated common-wire full rebuilds passed G1. These operation times are not source-to-image build times |
| r08_cow_index | Full G1 passed at28,393,611B,2.099s,12,756KiB. COW CRC/count/AVL/page-order checks passed |
| r09_cow_updates | All three updated full multisets and retained roots passed. Linux write_bytes57,344 /679,936 /117,510,144 |
| r10_matched_rocks_blocks | Native Zstd64KiB DNSRocks control full G1 passed at27,187,961B,2.457s,253,000KiB |
| r11_owner_order_updates | Archived06cc87 small update full G1 passed at write_bytes53,248. Medium delta rejected owner disorder. The earlier executable-permission failure was preserved separately; its algorithm never started |
| r12_key_representation | Same frozen2dcf binary, three full G1/COW checks passed. Nibble28,393,611B/5.3905s/12,672KiB; compact26,858,116B/4.2524s/12,696KiB; compact+next24,836,286B/1.9445s/12,704KiB. First two runs had1,245,799 and685,832 minor faults versus1,767 in the third, so the wall-time differences are not attributed entirely to the representation |
| COM size control | Independent-copy forced native Zstd64KiB recompression passed exact raw and canonical native-KV identity at6,021,850,878B, with fullBloom10 retained. Copy/verify/recompress times are separate from source-build metrics |

## Active work

Compact reversible owner keys and reversible NSEC3 next-hash reexpression are opt-in P1 candidates. Their generic semantics, five coded updates and three formal agency images passed qualification. Default-off output is byte-identical to the earlier reader. Old images and update roots remain readable. The next P1 step is a bounded COM cross-page NS/RDATA repetition census before deciding whether a global pool is justified.

## Thresholds and unverified scope

P1 >5x is unmet. The current best agency image24,836,286B is1.0947x smaller than matched native DNSRocks27,187,961B. The matched agency target is5,437,592.2B, while retained signature payload alone occupies16,882,944B and did not compress with the tested ordinary lossless stream codecs. This is empirical codec evidence, not an absolute entropy theorem.

P2's strict ratio against the old materialized path is unverified because that old output fails the requested multiset contract. Same-Z comparisons against the qualified native DNSRocks builder are valid. No full COM native ZimDB build or multi-size scaling result has been measured in this campaign.

P3 dirty-interval scaling is observed and all three r09 deltas passed G1. Medium and whole changes still write more than the stock native DNSRocks updater. That updater produces NoCompression new L0 SSTs over the retained Zstd base. A forced full-reencode control does not describe all LSM updates.

The owner-ordered input assumption for r11 medium was experimentally falsified. No medium/whole owner-mode result is inferred. Reordering preparation would need its own resource receipt before an unordered-input claim.

This research format and harness are local experimental changes. They have not been integrated into a production authoritative-server path or pushed to the public repository. Algorithmic novelty and the final silent-assumption sweep remain unverified.
