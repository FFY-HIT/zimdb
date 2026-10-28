# CoreDNS bogi plugin

1. `make -C ../../libbogi23`
2. Copy `bogi.go` to CoreDNS `plugin/bogi/`.
3. Add `bogi:bogi` to `plugin.cfg`.
4. Point `#cgo CFLAGS/LDFLAGS` in `bogi.go` at your `libbogi23` build, then rebuild CoreDNS.

```
example.org {
    bogi /path/to/image.bogi
}
```
