# Build Note

| Rung | Implementation | Acceptance | Status |
|---|---|---|---|
| F0 | Native source-to-image and tree-free lookup spine | validate.py --run-fixture with the archived binary | implemented, checks passed |
| F1 | Exact RR multiset and full name semantics | validate.py source/image/oracle qualification, plus semantic fixtures | agency G1 and generic semantics passed for qualified versions |
| F2 | Fixed-budget P2 performance | r14_qualified_reference complete cohort plus source/Counter G1 | agency stage passed,16.87x lower sampled tree RSS versus corrected materialized control |
| F3 | P1 pool/front-code/block-compression experiment | five r04 ablations and independent G1, plus r12 key-transform G1 | measured and qualified, 5x size target unmet |
| F4 | Atomic dirty-interval generation update | validate_updates.py against three delta sizes and retained roots | r15 current-format G1/roots/index passed; r16 matched encoding-core controls passed; observed dirty-scope scaling |

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
| r13_legacy_multiset_reference | Native and DNSRocks full G1 passed. The legacy multiplicity fix exposed one RRSIG duplicated by intentional parallel owner overlap; legacy G1 failed560148 versus560147. Preserve all rows and the failure |
| r14_qualified_reference | Disjoint source-record ownership plus multiplicity preservation qualified the legacy control. All three full multisets passed. Legacy36,641,408B/3.118099941s/213620KiB; native24,836,286B/1.924092253s/12664KiB; DNSRocks27,187,961B/2.333217043s/250748KiB |
| r15_current_updates | Current compact+next-key native and native DNSRocks updates passed all live/old-root G1 and index checks. Native W_IO57344/634880/103804928B and W_image32995/537373/24053347B. DNSRocks W_IO81920/114688/17178624B. Small command-IO ranking includes LOG/options/open-close costs; new small SST is1384B, so an algorithmic update advantage remains unestablished |
| r16_matched_full_reencode | Same r14 binaries/options, independently verified post-largest-delta common wire. Full encoding core W_IO native225816576B, DNSRocks54366208B, both complete source-plus-delta G1 passed. Prepared-wire creation and CURRENT cutover lie outside this operation |
| COM size control | Independent-copy forced native Zstd64KiB recompression passed exact raw and canonical native-KV identity at6,021,850,878B, with fullBloom10 retained. Copy/verify/recompress times are separate from source-build metrics |
| COM NS feasibility | One source pass verified441290102RR/406317943NS,1807445 unique NS targets. Independently decoded64KiB dictionary blocks model11071837B, fixed3-byte references1218953829B, total1230025666B. This NS-only model already exceeds the whole-image5x budget1204370175.6B. Census resource receipts are separate from build metrics |

## Active work

Compact reversible owner keys and reversible NSEC3 next-hash reexpression are opt-in P1 candidates. Their generic semantics, coded updates and full agency images passed qualification. Old images and update roots remain readable. The COM census falsified the fixed3-byte-per-RR NS-reference model against the5x budget. The next P1 priority is fully accounted RRset-level NS template/reference encoding, including reference entropy and metadata.

## Thresholds and unverified scope

P1 >5x is unmet. The current best agency image24,836,286B is1.0947x smaller than matched native DNSRocks27,187,961B. The matched agency target is5,437,592.2B, while retained signature payload alone occupies16,882,944B and did not compress with the tested ordinary lossless stream codecs. This is empirical codec evidence, not an absolute entropy theorem.

P2's stage threshold is supported on agency by the separately multiplicity/boundary-corrected legacy v2 control and native DNSRocks. The r14 sampled simultaneous tree-RSS ratios are16.8683x and19.8001x. Its native construction wall is38.293% lower than the corrected legacy control and17.535% lower than DNSRocks in this one trial. RSS sums can count shared pages across processes. Full COM native construction and a multi-size scaling curve remain pending evidence.

P3 dirty-scope scaling is observed and all three current r15 deltas passed G1. The largest workload replaces NS RRsets whose NS records have no covering RRSIG, covering123806 nonapex owners and294314 occurrences; all other records and DNSSEC bytes remain retained. Medium and largest native command write_bytes are5.54x and6.04x the stock native DNSRocks updater. That updater produces NoCompression new L0 SSTs over the retained Zstd base. The current largest-state incremental/full-core W_IO ratios are0.459687 for native and0.315980 for DNSRocks. Full-core input preparation and CURRENT publication are separate operations.

The owner-ordered input assumption for r11 medium was experimentally falsified. No medium/whole owner-mode result is inferred. Reordering preparation would need its own resource receipt before an unordered-input claim.

Queries currently use absolute in-origin names and an owner/type namespace over stored classes. All formal zone/query evidence is IN. ANY/0 is a private all-types selector distinct from literal255. The image still retains each RR class/type in full canonical export. Source-text missing-TTL seed3600, strict old-state delta removal semantics, common TAB/LF delta grammar, little-endian platform admission and codec/raw fallback policy are declared in the ledger.

The first same-family provisional silent-assumption sweep found9 missing contracts and3 stale protocol rows. The second sweep closed those records and three concrete CURRENT/publication issues, with0 remaining flags in its reviewed dc98d75 core scope. The review remains same-family/provisional. Later cohort/control parameter extensions were checked through their actual runs and G1 receipts. These research-format and harness changes are local experimental code.

## Current configuration

From the repository root, build with `make -C experiments/queryable_zone`. The native program links ldns1.8.4, LZ41.10.0, Zstd1.5.7 and libcrypto in the measured WSL environment. The independent oracle uses dnspython2.8.0.

```sh
experiments/queryable_zone/native_zone build \
  --zone SOURCE.zone --origin agency. --out FRESH/image.zim --work FRESH/work \
  --memory-mib 16 --codec zstd --pool none --front-code 1 \
  --index cow --key-codec compact --nsec3-next-key 1
```

Every round has STAGE.json, SUMMARY.json, raw sampler receipts and frozen code identities under the campaign root. DECISIONS.json links the raw results and qualification receipts for19 rounds/controls. P1's5x gate remains unmet and the total update advantage remains unestablished.
