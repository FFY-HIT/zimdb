package dnsserver

// This opt-in measurement hook records the existing ServeDNS timing scope.
// The fixed array is prefaulted before service starts. No file I/O, formatting,
// or allocation occurs while adding a request. SIGUSR1 dumps it after the
// client has stopped; this signal is reserved by this isolated experiment.
import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type queryTraceRecord struct {
	StartNS    uint64
	DurationNS uint64
	ID         uint16
	QType      uint16
	RCode      uint16
	Flags      uint16
	Reserved   uint64
}

var queryTraceEpoch = time.Now()
var queryTraceRecords []queryTraceRecord
var queryTraceUsed uint64
var queryTracePath string
var queryTraceMu sync.Mutex

func init() {
	queryTracePath = os.Getenv("DNSROCKS_QUERY_TRACE_PATH")
	if queryTracePath == "" {
		return
	}
	capacity := 65536
	if value := os.Getenv("DNSROCKS_QUERY_TRACE_CAPACITY"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000000 {
			panic("invalid DNSROCKS_QUERY_TRACE_CAPACITY")
		}
		capacity = n
	}
	queryTraceRecords = make([]queryTraceRecord, capacity)
	for i := range queryTraceRecords {
		queryTraceRecords[i].Reserved = uint64(i)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		for range signals {
			// The harness sends SIGUSR1 only while no client request is active.
			if err := dumpQueryTrace(); err != nil {
				fmt.Fprintln(os.Stderr, "query trace dump:", err)
			}
		}
	}()
}

func recordQueryTrace(start time.Time, duration time.Duration, r *dns.Msg, rcode int, err error) {
	if queryTraceRecords == nil {
		return
	}
	queryTraceMu.Lock()
	defer queryTraceMu.Unlock()
	i := queryTraceUsed
	queryTraceUsed++
	if i >= uint64(len(queryTraceRecords)) {
		return
	}
	flags := uint16(0)
	if err != nil {
		flags |= 1
	}
	qtype := uint16(0)
	if len(r.Question) == 1 {
		qtype = r.Question[0].Qtype
	} else {
		flags |= 2
	}
	queryTraceRecords[i] = queryTraceRecord{StartNS: uint64(start.Sub(queryTraceEpoch).Nanoseconds()),
		DurationNS: uint64(duration.Nanoseconds()), ID: r.Id, QType: qtype,
		RCode: uint16(rcode), Flags: flags}
}

func dumpQueryTrace() error {
	queryTraceMu.Lock()
	defer queryTraceMu.Unlock()
	used := queryTraceUsed
	count := used
	if count > uint64(len(queryTraceRecords)) {
		count = uint64(len(queryTraceRecords))
	}
	f, err := os.Create(queryTracePath + ".tmp")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(queryTracePath + ".tmp")
		}
	}()
	if _, err = f.Write([]byte("DRQTRC01")); err != nil {
		return err
	}
	for _, value := range []uint64{count, uint64(len(queryTraceRecords)), used - count} {
		if err = binary.Write(f, binary.LittleEndian, value); err != nil {
			return err
		}
	}
	if err = binary.Write(f, binary.LittleEndian, queryTraceRecords[:count]); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(queryTracePath+".tmp", queryTracePath); err != nil {
		return err
	}
	ok = true
	return nil
}
