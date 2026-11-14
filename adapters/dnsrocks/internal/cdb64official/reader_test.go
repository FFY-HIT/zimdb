package cdb64official

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "testing"
)

func TestOfficialBuilderDuplicateKeysAndContexts(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "native.cdb64")
    cmd := exec.Command("/home/administrator/compression12_20260919/tools/bin/cdb64make", path, path+".tmp")
    cmd.Stdin = bytes.NewBufferString("+3,3:key->one\n+3,3:key->two\n+4,5:else->other\n\n")
    if out, err := cmd.CombinedOutput(); err != nil { t.Fatalf("official maker: %v %s", err, out) }
    db, err := Open(path)
    if err != nil { t.Fatal(err) }
    defer db.Close()
    a, b := NewContext(), NewContext()
    db.FindStart(a); db.FindStart(b)
    for _, ctx := range []*Context{a, b} {
        first, err := db.FindNext([]byte("key"), ctx)
        if err != nil || string(first) != "one" { t.Fatalf("first = %q %v", first, err) }
    }
    for _, ctx := range []*Context{a, b} {
        second, err := db.FindNext([]byte("key"), ctx)
        if err != nil || string(second) != "two" { t.Fatalf("second = %q %v", second, err) }
        if _, err := db.FindNext([]byte("key"), ctx); err != io.EOF { t.Fatalf("EOF = %v", err) }
    }
    db.FindStart(a)
    if _, err := db.FindNext([]byte("missing"), a); err != io.EOF { t.Fatalf("missing = %v", err) }
}

func TestOfficialReaderOffsetBeyondFourGiB(t *testing.T) {
    // Tiny physical sparse fixture places an actual key/value and hash table
    // past 2^32. The official command and this binding must agree.
    path := filepath.Join(t.TempDir(), "offset64.cdb64")
    f, err := os.Create(path)
    if err != nil { t.Fatal(err) }
    key, value := []byte("offset-key"), []byte("beyond-4GiB")
    record := uint64(1<<32) + 4096
    table := record + 16 + uint64(len(key)+len(value))
    var h uint64 = 5381
    for _, c := range key { h = (h*33)^uint64(c) }
    header := make([]byte, 4096)
    binary.LittleEndian.PutUint64(header[(h&255)*16:], table)
    binary.LittleEndian.PutUint64(header[(h&255)*16+8:], 2)
    f.WriteAt(header, 0)
    row := make([]byte, 16+len(key)+len(value))
    binary.LittleEndian.PutUint64(row, uint64(len(key)))
    binary.LittleEndian.PutUint64(row[8:], uint64(len(value)))
    copy(row[16:], key); copy(row[16+len(key):], value)
    f.WriteAt(row, int64(record))
    slots := make([]byte, 32)
    off := ((h>>8)%2)*16
    binary.LittleEndian.PutUint64(slots[off:], h)
    binary.LittleEndian.PutUint64(slots[off+8:], record)
    f.WriteAt(slots, int64(table)); f.Close()
    db, err := Open(path)
    if err != nil { t.Fatal(err) }
    defer db.Close()
    ctx := NewContext(); db.FindStart(ctx)
    got, err := db.FindNext(key, ctx)
    if err != nil || !bytes.Equal(got, value) { t.Fatalf("64-bit lookup = %q %v", got, err) }
    input, err := os.Open(path)
    if err != nil { t.Fatal(err) }
    defer input.Close()
    cmd := exec.Command("/home/administrator/compression12_20260919/tools/bin/cdb64get", string(key))
    cmd.Stdin = input
    out, err := cmd.Output()
    if err != nil || !bytes.Equal(out, value) { t.Fatal(fmt.Sprintf("official get = %q %v", out, err)) }
}
