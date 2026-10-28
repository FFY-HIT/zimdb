# BIND ← ZimDB dyndb (`bogi_zonedb.so`)

mmap-direct zone DB: `named.conf` has no text `file` for the zone; load only mmaps `.bogi`.

## Build
```bash
# Point BIND_INC / BIND_DEPS at a BIND 9.20 install or unpacked -dev tree
make -C adapters/bind BIND_INC=/path/to/bind/include BIND_DEPS=/path/to/deps
```

Produces `bogi_zonedb.so`.

## Config
```text
dyndb "bogi" "/path/to/bogi_zonedb.so" {
    example.com. /path/to/image.bogi
};
```

## Layout
| File | Role |
|------|------|
| `src/db.c` | mmap-direct `dns_db` methods |
| `src/driver.c` / `instance.c` / `zone.c` / `log.c` | dyndb driver shell |
| `src/bogi23_reader.c` + `include/bogi23_*.h` | embedded ZimDB reader |
| `include-overlay/` | local BIND header overlays used by this module |
