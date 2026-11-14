package main

import (
    "bufio"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "math/bits"
    "os"
    "reflect"
    "time"
    "github.com/miekg/dns"
)

func check(err error) { if err != nil { panic(err) } }
func canonicalNames(value reflect.Value) {
    if value.Kind() == reflect.Ptr { value = value.Elem() }
    if value.Kind() != reflect.Struct { return }
    typ := value.Type()
    for i := 0; i < value.NumField(); i++ {
        field := value.Field(i)
        tag := typ.Field(i).Tag.Get("dns")
        if field.Kind() == reflect.String && field.CanSet() && (tag == "domain-name" || tag == "cdomain-name") {
            field.SetString(dns.CanonicalName(field.String()))
        }
        if field.Kind() == reflect.Struct { canonicalNames(field) }
    }
}
func add(sum *[4]uint64, digest [32]byte) {
    var carry uint64
    for i := 0; i < 4; i++ { sum[i],carry = bits.Add64(sum[i],binary.LittleEndian.Uint64(digest[i*8:i*8+8]),carry) }
}
func encode(sum [4]uint64) string {
    var data [32]byte
    for i := 0; i < 4; i++ { binary.LittleEndian.PutUint64(data[i*8:i*8+8],sum[i]) }
    return hex.EncodeToString(data[:])
}
func main() {
    zone := flag.String("zone","","Source zone; otherwise read canonical RR hex lines on stdin")
    origin := flag.String("origin","com.","Zone origin")
    flag.Parse()
    start := time.Now()
    var count, wireBytes uint64
    var first, second [4]uint64
    types := map[uint16]uint64{}
    buffer := make([]byte,66001)
    buffer[0] = 1
    consume := func(wire []byte) {
        position := 0
        for {
            if position >= len(wire) { panic("truncated owner") }
            n := int(wire[position]); position++
            if n == 0 { break }
            if n > 63 || position+n > len(wire) { panic("invalid canonical label") }
            position += n
        }
        if position+10 > len(wire) || position+10+int(binary.BigEndian.Uint16(wire[position+8:position+10])) != len(wire) { panic("incomplete RR") }
        if len(wire)+1 > len(buffer) { panic("RR exceeds standalone wire bound") }
        add(&first,sha256.Sum256(wire))
        copy(buffer[1:],wire)
        add(&second,sha256.Sum256(buffer[:len(wire)+1]))
        count++; wireBytes += uint64(len(wire)); types[binary.BigEndian.Uint16(wire[position:position+2])]++
        if count%8000000 == 0 { fmt.Fprintf(os.Stderr,"records=%d seconds=%.3f\n",count,time.Since(start).Seconds()) }
    }
    sourceHash := ""
    if *zone != "" {
        file,err := os.Open(*zone); check(err); defer file.Close()
        hash := sha256.New()
        parser := dns.NewZoneParser(bufio.NewReaderSize(io.TeeReader(file,hash),4<<20),*origin,*zone)
        parser.SetIncludeAllowed(false)
        for rr,ok := parser.Next(); ok; rr,ok = parser.Next() {
            rr.Header().Name = dns.CanonicalName(rr.Header().Name)
            canonicalNames(reflect.ValueOf(rr))
            data := make([]byte,dns.Len(rr)+8)
            n,err := dns.PackRR(rr,data,0,nil,false); check(err)
            consume(data[:n])
        }
        check(parser.Err()); sourceHash = hex.EncodeToString(hash.Sum(nil))
    } else {
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Buffer(make([]byte,256<<10),256<<10)
        for scanner.Scan() { data,err := hex.DecodeString(scanner.Text()); check(err); consume(data) }
        check(scanner.Err())
    }
    check(json.NewEncoder(os.Stdout).Encode(map[string]any{"records":count,"wire_bytes":wireBytes,"type_counts":types,
        "sha256_sum_mod_2_256_le":encode(first),"sha256_domain1_sum_mod_2_256_le":encode(second),
        "source_sha256":sourceHash,"seconds":time.Since(start).Seconds(),
        "protocol":"Two domain-separated SHA256 multiset-sum fingerprints, exact occurrence/type counts; bounded streaming probabilistic verification"}))
}
