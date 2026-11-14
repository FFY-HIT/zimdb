// DNSRocks native representation controls for build, export, and atomic batch updates.
// Assumptions RDB001-RDB006 are recorded in ASSUMPTIONS.md before this code.
// Codec helpers reuse the qualified agency frontend and validate complete RR wire.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	rocksdb "github.com/facebook/dns/dnsrocks/cgo-rocksdb"
	dnsdb "github.com/facebook/dns/dnsrocks/db"
	"github.com/facebook/dns/dnsrocks/dnsdata"
	"github.com/facebook/dns/dnsrocks/dnsdata/rdb"
	"github.com/miekg/dns"
)

type configuration struct {
	mode, zone, wireInput, origin, output, database, delta, codec, stats string
	retainedCheckpoint                                                   string
	blockBytes                                                           uint64
}

type fileIdentity struct {
	Name           string `json:"name"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256,omitempty"`
	Device         uint64 `json:"device"`
	Inode          uint64 `json:"inode"`
	Links          uint64 `json:"link_count"`
	AllocatedBytes int64  `json:"allocated_bytes"`
}

func require(err error) {
	if err != nil {
		panic(err)
	}
}

func emit(document any) {
	b, err := json.Marshal(document)
	require(err)
	fmt.Println(string(b))
}

func stage(start time.Time, name, event string) {
	emit(map[string]any{"type": "STAGE", "stage": name, "event": event, "elapsed_seconds": time.Since(start).Seconds()})
}

func summary(config configuration, document map[string]any) {
	document["type"] = "SUMMARY"
	document["mode"] = config.mode
	document["backend"] = "DNSRocks+RocksDB"
	document["dnsrocks_commit"] = "943c50fe80340760c44aeeb0d3460e527cbc5339"
	document["runtime_numcpu"] = runtime.NumCPU()
	document["gomaxprocs"] = runtime.GOMAXPROCS(0)
	if config.stats != "" {
		b, err := json.MarshalIndent(document, "", "  ")
		require(err)
		require(os.WriteFile(config.stats+".tmp", append(b, '\n'), 0644))
		require(os.Rename(config.stats+".tmp", config.stats))
	}
	emit(document)
}

func lowerNames(v reflect.Value) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		tag := typ.Field(i).Tag.Get("dns")
		if field.Kind() == reflect.String && field.CanSet() && (tag == "domain-name" || tag == "cdomain-name") {
			field.SetString(dns.CanonicalName(field.String()))
		}
		if field.Kind() == reflect.Struct {
			lowerNames(field)
		}
	}
}

func rrWire(rr dns.RR) []byte {
	rr.Header().Name = dns.CanonicalName(rr.Header().Name)
	lowerNames(reflect.ValueOf(rr))
	b := make([]byte, dns.Len(rr)+8)
	n, err := dns.PackRR(rr, b, 0, nil, false)
	require(err)
	return b[:n]
}

func rrParts(wire []byte) (string, int, []byte) {
	name, offset, err := dns.UnpackDomainName(wire, 0)
	require(err)
	if offset+10 > len(wire) {
		panic("short RR header")
	}
	length := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
	if offset+10+length != len(wire) {
		panic("RR length mismatch")
	}
	return name, offset, wire[offset+10:]
}

func validateCanonical(wire []byte) {
	rr, end, err := dns.UnpackRR(wire, 0)
	require(err)
	if end != len(wire) || !bytes.Equal(rrWire(rr), wire) {
		panic("input wire RR is not complete canonical uncompressed wire")
	}
}

func auxLine(wire []byte) []byte {
	name, offset, data := rrParts(wire)
	typeCode := binary.BigEndian.Uint16(wire[offset : offset+2])
	ttl := binary.BigEndian.Uint32(wire[offset+4 : offset+8])
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '*') {
			panic(fmt.Sprintf("native DNSRocks text codec cannot roundtrip this owner %q", name))
		}
	}
	if typeCode == dns.TypeA || typeCode == dns.TypeAAAA {
		ip := net.IP(data)
		if (typeCode == dns.TypeA && len(data) != 4) || (typeCode == dns.TypeAAAA && len(data) != 16) {
			panic("invalid address RDATA width")
		}
		if typeCode == dns.TypeAAAA && ip.To4() != nil {
			panic("native Raddr coerces mapped AAAA to A")
		}
		return []byte(fmt.Sprintf("+%s,%s,%d,,,1", name, ip.String(), ttl))
	}
	b := append([]byte{':'}, name...)
	b = append(b, ',')
	b = strconv.AppendUint(b, uint64(typeCode), 10)
	b = append(b, ',')
	for _, c := range data {
		b = append(b, '\\', byte('0'+(c>>6)), byte('0'+((c>>3)&7)), byte('0'+(c&7)))
	}
	b = append(b, ',')
	b = strconv.AppendUint(b, uint64(ttl), 10)
	return append(b, ',', ',')
}

func nativeWire(record dnsdata.MapRecord) []byte {
	key, value := record.Key, record.Value
	if len(value) < 15 {
		panic("short native RR row")
	}
	wildcard := value[2] == '*' || value[2] == '*'+1
	decoded, err := dnsdb.ExtractRRFromRow(value, wildcard)
	require(err)
	if (!wildcard && value[2] != '=') || decoded.Offset > len(value) {
		panic("unsupported located native RR row")
	}
	if (decoded.Qtype == dns.TypeA || decoded.Qtype == dns.TypeAAAA) && decoded.Weight != 1 {
		panic("unexpected native address weight")
	}
	if len(key) < 5 || key[0] != 0 || key[1] != 'o' {
		panic("expected default-location v2 native key")
	}
	p := 2
	var labels [][]byte
	for {
		if p >= len(key) {
			panic("truncated v2 native name")
		}
		n := int(key[p])
		p++
		if n == 0 {
			break
		}
		if p+n > len(key) {
			panic("invalid v2 native label")
		}
		labels = append(labels, key[p:p+n])
		p += n
	}
	if p+2 != len(key) || key[p] != 0 || key[p+1] != 0 {
		panic("unsupported native location")
	}
	var wire []byte
	if wildcard {
		wire = append(wire, 1, '*')
	}
	for i := len(labels) - 1; i >= 0; i-- {
		wire = append(wire, byte(len(labels[i])))
		wire = append(wire, labels[i]...)
	}
	wire = append(wire, 0)
	wire = append(wire, value[:2]...)
	wire = append(wire, 0, 1)
	wire = append(wire, value[3:7]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(value)-decoded.Offset))
	return append(wire, value[decoded.Offset:]...)
}

func nativeRecord(codec *dnsdata.Codec, wire []byte) dnsdata.MapRecord {
	_, offset, _ := rrParts(wire)
	if binary.BigEndian.Uint16(wire[offset+2:offset+4]) != dns.ClassINET {
		panic("native DNSRocks baseline only admits IN class")
	}
	records, err := codec.ConvertLn(auxLine(wire))
	require(err)
	if len(records) != 1 || !bytes.Equal(nativeWire(records[0]), wire) {
		panic("native DNSRocks codec lost canonical RR bytes")
	}
	return records[0]
}

func newCodec() *dnsdata.Codec {
	codec := new(dnsdata.Codec)
	codec.Features.UseV2Keys = true
	return codec
}

func metadata(codec *dnsdata.Codec) []dnsdata.MapRecord {
	a, err := codec.Acc.MarshalMap()
	require(err)
	b, err := codec.Features.MarshalMap()
	require(err)
	return append(a, b...)
}

func readSource(config configuration, consume func([]byte)) (int64, string) {
	path := config.zone
	if config.wireInput != "" {
		path = config.wireInput
	}
	file, err := os.Open(path)
	require(err)
	defer file.Close()
	info, err := file.Stat()
	require(err)
	hash := sha256.New()
	input := io.TeeReader(file, hash)
	if config.wireInput != "" {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64<<10), 256<<10)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			wire, err := hex.DecodeString(string(line))
			require(err)
			validateCanonical(wire)
			consume(wire)
		}
		require(scanner.Err())
	} else {
		parser := dns.NewZoneParser(bufio.NewReaderSize(input, 4<<20), config.origin, config.zone)
		parser.SetIncludeAllowed(false)
		for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
			consume(rrWire(rr))
		}
		require(parser.Err())
	}
	return info.Size(), hex.EncodeToString(hash.Sum(nil))
}

func ioCounters() map[string]uint64 {
	data, err := os.ReadFile("/proc/self/io")
	require(err)
	result := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			value, err := strconv.ParseUint(parts[1], 10, 64)
			require(err)
			result[strings.TrimSuffix(parts[0], ":")] = value
		}
	}
	return result
}

func difference(after, before map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64)
	for key, value := range after {
		if value >= before[key] {
			result[key] = value - before[key]
		}
	}
	return result
}

func files(database string, hashSST bool) []fileIdentity {
	entries, err := os.ReadDir(database)
	require(err)
	var result []fileIdentity
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		require(err)
		row := fileIdentity{Name: entry.Name(), Bytes: info.Size()}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			panic("file accounting requires Linux stat identity")
		}
		row.Device = stat.Dev
		row.Inode = stat.Ino
		row.Links = stat.Nlink
		row.AllocatedBytes = stat.Blocks * 512
		if hashSST && strings.HasSuffix(row.Name, ".sst") {
			file, err := os.Open(filepath.Join(database, row.Name))
			require(err)
			hash := sha256.New()
			_, err = io.Copy(hash, file)
			require(err)
			require(file.Close())
			row.SHA256 = hex.EncodeToString(hash.Sum(nil))
		}
		result = append(result, row)
	}
	return result
}

func nativeSize(rows []fileIdentity) (int64, int64) {
	var native, all int64
	for _, row := range rows {
		all += row.Bytes
		if row.Name != "LOCK" && row.Name != "LOG" && !strings.HasPrefix(row.Name, "LOG.old.") {
			native += row.Bytes
		}
	}
	return native, all
}

func retainedAccounting(database, checkpoint string) map[string]any {
	type inodeIdentity struct{ device, inode uint64 }
	allSeen := make(map[inodeIdentity]bool)
	nativeSeen := make(map[inodeIdentity]bool)
	var uniqueLogical, uniqueAllocated, nativeLogical, nativeAllocated int64
	var pathLogical, pathAllocated int64
	var sharedSSTPaths int
	for _, directory := range []string{database, checkpoint} {
		for _, row := range files(directory, false) {
			identity := inodeIdentity{row.Device, row.Inode}
			pathLogical += row.Bytes
			pathAllocated += row.AllocatedBytes
			if allSeen[identity] {
				if strings.HasSuffix(row.Name, ".sst") {
					sharedSSTPaths++
				}
			} else {
				allSeen[identity] = true
				uniqueLogical += row.Bytes
				uniqueAllocated += row.AllocatedBytes
			}
			if row.Name != "LOG" && row.Name != "LOCK" && !strings.HasPrefix(row.Name, "LOG.old.") && !nativeSeen[identity] {
				nativeSeen[identity] = true
				nativeLogical += row.Bytes
				nativeAllocated += row.AllocatedBytes
			}
		}
	}
	return map[string]any{
		"live_database": database, "previous_checkpoint": checkpoint, "retained_previous_generations": 1,
		"unique_inode_count": len(allSeen), "shared_sst_additional_paths": sharedSSTPaths,
		"all_unique_inode_logical_bytes": uniqueLogical, "all_unique_inode_allocated_bytes": uniqueAllocated,
		"native_unique_inode_logical_bytes": nativeLogical, "native_unique_inode_allocated_bytes": nativeAllocated,
		"all_path_logical_bytes_before_inode_dedup": pathLogical, "all_path_allocated_bytes_before_inode_dedup": pathAllocated,
		"scope": "live and one previous checkpoint; device+inode dedup; allocated=st_blocks*512; no reflink extent dedup claim",
	}
}

func syncDatabase(database string) {
	for _, row := range files(database, false) {
		file, err := os.Open(filepath.Join(database, row.Name))
		require(err)
		require(file.Sync())
		require(file.Close())
	}
	for _, path := range []string{database, filepath.Dir(database)} {
		file, err := os.Open(path)
		require(err)
		require(file.Sync())
		require(file.Close())
	}
}

func peakRSS() int64 {
	var usage syscall.Rusage
	require(syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	return usage.Maxrss
}

func runBuild(config configuration) {
	if _, err := os.Stat(config.output); !os.IsNotExist(err) {
		panic("build output must not exist")
	}
	require(os.Setenv("ZIMDB_EXPERIMENT_RDB_SST_CODEC", config.codec))
	if config.blockBytes == 0 {
		require(os.Unsetenv("ZIMDB_EXPERIMENT_RDB_BLOCK_BYTES"))
	} else {
		require(os.Setenv("ZIMDB_EXPERIMENT_RDB_BLOCK_BYTES", strconv.FormatUint(config.blockBytes, 10)))
	}
	start := time.Now()
	beforeIO := ioCounters()
	stage(start, "open", "start")
	require(os.MkdirAll(config.output, 0755))
	builder, err := rdb.NewBuilder(config.output, false)
	require(err)
	stage(start, "open", "end")
	codec := newCodec()
	var records, mapRecords uint64
	types := make(map[uint16]uint64)
	stage(start, "parse_canonicalize_native_convert_schedule", "start")
	parseStart := time.Now()
	inputBytes, inputSHA := readSource(config, func(wire []byte) {
		record := nativeRecord(codec, wire)
		builder.ScheduleAdd(record)
		_, offset, _ := rrParts(wire)
		types[binary.BigEndian.Uint16(wire[offset:offset+2])]++
		records++
		mapRecords++
	})
	for _, record := range metadata(codec) {
		builder.ScheduleAdd(record)
		mapRecords++
	}
	parseSeconds := time.Since(parseStart).Seconds()
	stage(start, "parse_canonicalize_native_convert_schedule", "end")
	stage(start, "stock_sort_merge_sst_ingest_compact", "start")
	buildStart := time.Now()
	require(builder.Execute())
	buildSeconds := time.Since(buildStart).Seconds()
	stage(start, "stock_sort_merge_sst_ingest_compact", "end")
	stage(start, "close", "start")
	builder.FreeBuilder()
	stage(start, "close", "end")
	commandSeconds := time.Since(start).Seconds()
	stage(start, "durable_sync", "start")
	syncDatabase(config.output)
	stage(start, "durable_sync", "end")
	durableSeconds := time.Since(start).Seconds()
	afterIO := ioCounters()
	identities := files(config.output, false)
	native, directory := nativeSize(identities)
	summary(config, map[string]any{
		"status": "BUILT_PENDING_G1_AND_SEMANTIC_QUERY_CHECKS", "codec": config.codec,
		"requested_sst_block_bytes": config.blockBytes,
		"block_size_scope":          "zero preserves upstream default; nonzero sets native SST data-block target only",
		"source_zone":               config.zone, "input_wire_hex": config.wireInput, "input_bytes": inputBytes, "input_sha256": inputSHA,
		"origin": config.origin, "output": config.output, "raw_rr_occurrences": records, "native_map_records": mapRecords,
		"raw_rr_counts_by_type": types, "parse_canonicalize_convert_schedule_seconds": parseSeconds,
		"stock_builder_execute_seconds": buildSeconds, "command_before_extra_fsync_seconds": commandSeconds,
		"durable_seconds": durableSeconds, "self_peak_rss_kib": peakRSS(), "native_bytes": native,
		"directory_bytes_including_diagnostics": directory, "files": identities, "process_io_delta": difference(afterIO, beforeIO),
		"scope": "native DNSRocks builder and representation, source or common-wire frontend through close and all-file/directory fsync",
	})
}

func runUpdate(config configuration) {
	beforeFiles := files(config.database, true)
	beforeIO := ioCounters()
	start := time.Now()
	stage(start, "open_native_updater", "start")
	updater, err := rdb.NewUpdater(config.database)
	require(err)
	stage(start, "open_native_updater", "end")
	codec := newCodec()
	batch := updater.CreateBatch()
	deltaFile, err := os.Open(config.delta)
	require(err)
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(deltaFile, hash))
	scanner.Buffer(make([]byte, 64<<10), 256<<10)
	var added, deleted, logicalBytes uint64
	affected := make(map[string]bool)
	stage(start, "parse_delta_convert_schedule", "start")
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 0 {
			continue
		}
		if len(parts) != 2 || (parts[0] != "+" && parts[0] != "-") {
			panic("delta line requires + or - followed by complete canonical RR wire hex")
		}
		wire, err := hex.DecodeString(parts[1])
		require(err)
		validateCanonical(wire)
		record := nativeRecord(codec, wire)
		affected[string(record.Key)] = true
		logicalBytes += uint64(len(wire))
		if parts[0] == "+" {
			batch.Add(record.Key, record.Value)
			added++
		} else {
			batch.Del(record.Key, record.Value)
			deleted++
		}
	}
	require(scanner.Err())
	require(deltaFile.Close())
	stage(start, "parse_delta_convert_schedule", "end")
	stage(start, "native_atomic_execute_batch", "start")
	require(updater.ExecuteBatch(batch))
	stage(start, "native_atomic_execute_batch", "end")
	batchVisibleSeconds := time.Since(start).Seconds()
	statsBeforeClose := updater.GetStats()
	stage(start, "close_flush_wait_compaction", "start")
	require(updater.Close())
	stage(start, "close_flush_wait_compaction", "end")
	closeSeconds := time.Since(start).Seconds()
	stage(start, "durable_sync", "start")
	syncDatabase(config.database)
	stage(start, "durable_sync", "end")
	durableSeconds := time.Since(start).Seconds()
	afterIO := ioCounters()
	afterFiles := files(config.database, true)
	previous := make(map[string]fileIdentity)
	for _, row := range beforeFiles {
		previous[row.Name] = row
	}
	var newSSTBytes int64
	var newSST []fileIdentity
	for _, row := range afterFiles {
		if strings.HasSuffix(row.Name, ".sst") && previous[row.Name].SHA256 != row.SHA256 {
			newSSTBytes += row.Bytes
			newSST = append(newSST, row)
		}
	}
	native, directory := nativeSize(afterFiles)
	document := map[string]any{
		"status": "UPDATED_PENDING_G1_AND_SEMANTIC_QUERY_CHECKS", "database": config.database,
		"delta": config.delta, "delta_sha256": hex.EncodeToString(hash.Sum(nil)),
		"added_rr_occurrences": added, "deleted_rr_occurrences": deleted,
		"affected_native_keys": len(affected), "logical_delta_rr_wire_bytes": logicalBytes,
		"native_bytes": native, "directory_bytes_including_diagnostics": directory,
		"atomic_batch_visible_seconds": batchVisibleSeconds, "close_flush_complete_seconds": closeSeconds,
		"durable_seconds": durableSeconds, "self_peak_rss_kib": peakRSS(),
		"process_io_delta": difference(afterIO, beforeIO), "new_or_changed_live_sst_bytes": newSSTBytes,
		"new_or_changed_live_sst_files": newSST, "files_before": beforeFiles, "files_after": afterFiles,
		"native_stats_before_close": statsBeforeClose,
		"durability":                "stock updater WAL disabled; atomic batch visibility, then Close flush/wait plus all-file/directory fsync",
		"write_accounting":          "process write_bytes/wchar/cancelled_write_bytes include open, conversion, batch, close/compaction and durable sync; live SST differences omit deleted transient SSTs",
	}
	if config.retainedCheckpoint != "" {
		document["retention_accounting"] = retainedAccounting(config.database, config.retainedCheckpoint)
	}
	summary(config, document)
}

func runCheckpoint(config configuration) {
	if _, err := os.Stat(config.output); !os.IsNotExist(err) {
		panic("checkpoint output must not exist")
	}
	start := time.Now()
	beforeIO := ioCounters()
	stage(start, "open_checkpoint_source", "start")
	options := rdb.DefaultOptions()
	database, err := rocksdb.OpenDatabase(config.database, false, false, options)
	if err != nil {
		options.FreeOptions()
		require(err)
	}
	stage(start, "open_checkpoint_source", "end")
	stage(start, "native_checkpoint", "start")
	require(database.CreateCheckpoint(config.output))
	stage(start, "native_checkpoint", "end")
	database.CloseDatabase()
	stage(start, "checkpoint_durable_sync", "start")
	syncDatabase(config.database)
	syncDatabase(config.output)
	stage(start, "checkpoint_durable_sync", "end")
	durableSeconds := time.Since(start).Seconds()
	afterIO := ioCounters()
	summary(config, map[string]any{
		"status": "CHECKPOINT_PREPARED_PENDING_OLD_GENERATION_G1", "database": config.database,
		"checkpoint": config.output, "durable_seconds": durableSeconds,
		"self_peak_rss_kib": peakRSS(), "process_io_delta": difference(afterIO, beforeIO),
		"native_api": "rocksdb_checkpoint_object_create + rocksdb_checkpoint_create(log_size_for_flush=0)",
		"files_live": files(config.database, false), "files_checkpoint": files(config.output, false),
		"retention_accounting": retainedAccounting(config.database, config.output),
		"scope":                "previous-generation preparation outside update W timer; native SST sharing; live working copy is opened read-write",
	})
}

func runWire(config configuration) {
	options := rdb.DefaultOptions()
	database, err := rocksdb.OpenDatabase(config.database, true, false, options)
	if err != nil {
		options.FreeOptions()
		require(err)
	}
	defer database.CloseDatabase()
	readOptions := rocksdb.NewDefaultReadOptions()
	defer readOptions.FreeReadOptions()
	iterator := database.CreateIterator(readOptions)
	defer iterator.FreeIterator()
	writer := bufio.NewWriterSize(os.Stdout, 1<<20)
	for iterator.SeekToFirst(); iterator.IsValid(); iterator.Next() {
		key, values := iterator.Key(), iterator.Value()
		if !nativeRecordKey(key) {
			continue
		}
		for len(values) > 0 {
			value, remaining, err := rdb.ReadNextChunk(values)
			require(err)
			wire := nativeWire(dnsdata.MapRecord{Key: key, Value: value})
			_, err = fmt.Fprintln(writer, hex.EncodeToString(wire))
			require(err)
			values = remaining
		}
	}
	require(iterator.GetError())
	require(writer.Flush())
}

func nativeRecordKey(key []byte) bool {
	if len(key) < 5 || key[0] != 0 || key[1] != 'o' {
		return false
	}
	position := 2
	for position < len(key) {
		length := int(key[position])
		position++
		if length == 0 {
			return position+2 == len(key) && key[position] == 0 && key[position+1] == 0
		}
		if length > 63 || position+length > len(key) {
			return false
		}
		position += length
	}
	return false
}

func parseConfiguration() configuration {
	if len(os.Args) < 2 {
		panic("usage: rocks_control build|update|checkpoint|wire [options]")
	}
	config := configuration{mode: os.Args[1]}
	flags := flag.NewFlagSet(config.mode, flag.ExitOnError)
	flags.StringVar(&config.zone, "zone", "", "complete zone source")
	flags.StringVar(&config.wireInput, "input-wire-hex", "", "canonical complete wire RR hex per occurrence")
	flags.StringVar(&config.origin, "origin", "agency.", "zone origin")
	flags.StringVar(&config.output, "out", "", "new database directory")
	flags.StringVar(&config.database, "db", "", "existing native database")
	flags.StringVar(&config.delta, "delta", "", "complete RRset old/new members as +/- wirehex lines")
	flags.StringVar(&config.codec, "codec", "lz4", "SST compression snappy/lz4/zstd")
	flags.StringVar(&config.stats, "stats", "", "SUMMARY JSON output")
	flags.StringVar(&config.retainedCheckpoint, "retained-checkpoint", "", "previous checkpoint retained during update")
	flags.Uint64Var(&config.blockBytes, "block-bytes", 0, "native SST block target bytes; zero keeps upstream default")
	require(flags.Parse(os.Args[2:]))
	if config.codec != "snappy" && config.codec != "lz4" && config.codec != "zstd" {
		panic("codec must be snappy, lz4 or zstd")
	}
	return config
}

func unusedOriginalMain() {
	config := parseConfiguration()
	switch config.mode {
	case "build":
		if config.output == "" || (config.zone == "") == (config.wireInput == "") {
			panic("build requires --out and exactly one of --zone or --input-wire-hex")
		}
		runBuild(config)
	case "update":
		if config.database == "" || config.delta == "" {
			panic("update requires --db and --delta")
		}
		runUpdate(config)
	case "wire":
		if config.database == "" {
			panic("wire requires --db")
		}
		runWire(config)
	case "checkpoint":
		if config.database == "" || config.output == "" {
			panic("checkpoint requires --db and --out")
		}
		runCheckpoint(config)
	default:
		panic("unknown mode")
	}
}
