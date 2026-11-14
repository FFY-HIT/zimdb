package db

// Optional on-demand storage API: filters pool payload reads, while reporting
// owner existence independently so typed misses still produce NODATA, not NXDOMAIN.
// Drivers not implementing it keep their exact existing ForEach implementation.
type typedDBI interface {
    ForEachTypes(key []byte, types []uint16, wildcard bool, f func([]byte) error, context Context) (bool, error)
}

type wildcardBoundaryDBI interface {
    WildcardBoundary(key []byte, context Context) (bool, error)
}

func (r *DataReader) wildcardBoundary(key []byte) (bool, error) {
    if driver, okay := r.db.dbi.(wildcardBoundaryDBI); okay {
        return driver.WildcardBoundary(key, r.context)
    }
    return false, nil
}

func (r *DataReader) forEachTypes(key []byte, types []uint16, wildcard bool, f func([]byte) error) (bool, error) {
    if driver, okay := r.db.dbi.(typedDBI); okay {
        return driver.ForEachTypes(key, types, wildcard, f, r.context)
    }
    return false, r.ForEach(key, f)
}

func forEachResourceRecordTypes(r Reader, domain []byte, location ID, types []uint16, f func([]byte) error) error {
    // The native ZimDB is unlocated v1. Preserve sorted/v2 readers' original
    // dispatch and all legacy drivers' code paths without a schema conversion.
    if reader, okay := r.(*DataReader); okay {
        if _, typed := reader.db.dbi.(typedDBI); typed {
            if !location.IsZero() {
                key := append(append([]byte{}, location...), domain...)
                if _, err := reader.forEachTypes(key, types, false, f); err != nil { return err }
            }
            key := append(append([]byte{}, ZeroID...), domain...)
            _, err := reader.forEachTypes(key, types, false, f)
            return err
        }
    }
    return r.ForEachResourceRecord(domain, location, f)
}
