package main

import (
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "math/bits"
 "os"
 "time"
 rocksdb "github.com/facebook/dns/dnsrocks/cgo-rocksdb"
 "github.com/facebook/dns/dnsrocks/dnsdata"
 "github.com/facebook/dns/dnsrocks/dnsdata/rdb"
)

func main(){
 c:=parseConfiguration()
 start:=time.Now()
 options:=rdb.DefaultOptions()
 db,err:=rocksdb.OpenDatabase(c.database,true,false,options);require(err)
 defer db.CloseDatabase()
 read:=rocksdb.NewDefaultReadOptions();defer read.FreeReadOptions()
 iterator:=db.CreateIterator(read);defer iterator.FreeIterator()
 var count,wireBytes uint64
 var first,second [4]uint64
 types:=map[uint16]uint64{}
 buffer:=make([]byte,66001);buffer[0]=1
 add:=func(sum *[4]uint64,digest [32]byte){var carry uint64
   for i:=0;i<4;i++{sum[i],carry=bits.Add64(sum[i],binary.LittleEndian.Uint64(digest[i*8:i*8+8]),carry)}}
 for iterator.SeekToFirst();iterator.IsValid();iterator.Next(){
   key,values:=iterator.Key(),iterator.Value()
   if !nativeRecordKey(key){continue}
   for len(values)>0{
     value,rest,err:=rdb.ReadNextChunk(values);require(err)
     wire:=nativeWire(dnsdata.MapRecord{Key:key,Value:value})
     _,position,_:=rrParts(wire)
     add(&first,sha256.Sum256(wire));copy(buffer[1:],wire)
     add(&second,sha256.Sum256(buffer[:len(wire)+1]))
     count++;wireBytes+=uint64(len(wire));types[binary.BigEndian.Uint16(wire[position:position+2])]++
     values=rest
   }
 }
 require(iterator.GetError())
 encode:=func(sum [4]uint64)string{var data [32]byte;for i:=0;i<4;i++{binary.LittleEndian.PutUint64(data[i*8:i*8+8],sum[i])};return hex.EncodeToString(data[:])}
 require(json.NewEncoder(os.Stdout).Encode(map[string]any{"records":count,"wire_bytes":wireBytes,"type_counts":types,
   "sha256_sum_mod_2_256_le":encode(first),"sha256_domain1_sum_mod_2_256_le":encode(second),
   "seconds":time.Since(start).Seconds(),"protocol":"complete native DNSRocks RR multiset, two SHA256 sums and exact counts; probabilistic verification"}))
}
