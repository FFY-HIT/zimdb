// Source-derived workload and closed-loop DNS client. The measured system never
// supplies its own oracle. Request packing and answer validation are untimed.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Query struct {
	Name     string   `json:"name"`
	Type     uint16   `json:"type"`
	Category string   `json:"category"`
	Rcode    int      `json:"rcode"`
	AA       bool     `json:"aa"`
	Section  string   `json:"section"`
	Expected []string `json:"expected_rr_wire_hex"`
}
type Sample struct {
	Count    int     `json:"count"`
	MeanUS   float64 `json:"mean_us"`
	MedianUS float64 `json:"median_us"`
	P95US    float64 `json:"p95_us"`
	P99US    float64 `json:"p99_us"`
	MaxUS    float64 `json:"max_us"`
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func save(path string, value any) {
	p, e := json.MarshalIndent(value, "", "  ")
	check(e)
	check(os.WriteFile(path, append(p, '\n'), 0644))
}
func canonical(rr dns.RR) string {
	copy := dns.Copy(rr)
	copy.Header().Name = dns.CanonicalName(copy.Header().Name)
	switch r := copy.(type) {
	case *dns.NS:
		r.Ns = dns.CanonicalName(r.Ns)
	case *dns.SOA:
		r.Ns = dns.CanonicalName(r.Ns)
		r.Mbox = dns.CanonicalName(r.Mbox)
	case *dns.CNAME:
		r.Target = dns.CanonicalName(r.Target)
	}
	wire := make([]byte, dns.Len(copy)+512)
	end, e := dns.PackRR(copy, wire, 0, nil, false)
	check(e)
	return hex.EncodeToString(wire[:end])
}
func unique(rrs []dns.RR) []string {
	set := map[string]bool{}
	for _, rr := range rrs {
		set[canonical(rr)] = true
	}
	out := []string{}
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
func loadQueries(path string) []Query {
	file, e := os.Open(path)
	check(e)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	out := []Query{}
	for scanner.Scan() {
		var query Query
		check(json.Unmarshal(scanner.Bytes(), &query))
		out = append(out, query)
	}
	check(scanner.Err())
	return out
}
func writeQueries(path string, queries []Query) {
	file, e := os.Create(path)
	check(e)
	defer file.Close()
	writer := bufio.NewWriterSize(file, 1<<20)
	for _, query := range queries {
		b, e := json.Marshal(query)
		check(e)
		_, e = writer.Write(append(b, '\n'))
		check(e)
	}
	check(writer.Flush())
}
func prepare(root string) {
	source, e := os.Open(filepath.Join(root, "selected_source.zone"))
	check(e)
	defer source.Close()
	parser := dns.NewZoneParser(bufio.NewReaderSize(source, 1<<20), "com.", "selected_source.zone")
	parser.SetIncludeAllowed(false)
	owners := map[string]map[uint16][]dns.RR{}
	counts := map[uint16]int{}
	rows := 0
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		name := dns.CanonicalName(rr.Header().Name)
		if owners[name] == nil {
			owners[name] = map[uint16][]dns.RR{}
		}
		typ := rr.Header().Rrtype
		owners[name][typ] = append(owners[name][typ], rr)
		counts[typ]++
		rows++
	}
	check(parser.Err())
	roles, e := os.ReadFile(filepath.Join(root, "owner_roles.tsv"))
	check(e)
	delegates, signed := []string{}, []string{}
	for _, line := range strings.Split(string(roles), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			continue
		}
		if fields[0] == "delegation" {
			delegates = append(delegates, fields[2])
		} else if fields[0] == "signed" {
			signed = append(signed, fields[2])
		}
	}
	rng := rand.New(rand.NewSource(20261114))
	rng.Shuffle(len(delegates), func(i, j int) { delegates[i], delegates[j] = delegates[j], delegates[i] })
	rng.Shuffle(len(signed), func(i, j int) { signed[i], signed[j] = signed[j], signed[i] })
	negativeFile, e := os.ReadFile(filepath.Join(root, "negative_names.txt"))
	check(e)
	negative := strings.Fields(string(negativeFile))
	rng.Shuffle(len(negative), func(i, j int) { negative[i], negative[j] = negative[j], negative[i] })
	soa := unique(owners["com."][dns.TypeSOA])
	if len(soa) != 1 {
		panic("source apex SOA oracle not unique")
	}
	unsigned := []string{}
	for _, name := range delegates {
		if len(owners[name][dns.TypeDS]) == 0 {
			unsigned = append(unsigned, name)
		}
	}
	if len(delegates) < 50000 || len(signed) < 22000 || len(unsigned) < 22000 || len(negative) < 22000 {
		panic("insufficient sampled classes")
	}
	makeQuery := func(category, name, owner string) Query {
		q := Query{Name: name, Category: category, Rcode: dns.RcodeSuccess, AA: false, Type: dns.TypeA, Section: "authority"}
		switch category {
		case "delegation_A", "below_cut_A":
			q.Expected = unique(owners[owner][dns.TypeNS])
			if len(q.Expected) == 0 {
				panic("missing source NS")
			}
		case "signed_DS":
			q.Type = dns.TypeDS
			q.AA = true
			q.Section = "answer"
			q.Expected = unique(owners[name][dns.TypeDS])
			if len(q.Expected) == 0 {
				panic("missing source DS")
			}
		case "unsigned_DS":
			q.Type = dns.TypeDS
			q.AA = true
			q.Expected = soa
		case "absent_A":
			q.Rcode = dns.RcodeNameError
			q.AA = true
			q.Expected = soa
		default:
			panic(category)
		}
		return q
	}
	queries, warmup := []Query{}, []Query{}
	for i := 0; i < 20000; i++ {
		queries = append(queries, makeQuery("delegation_A", delegates[i], delegates[i]), makeQuery("signed_DS", signed[i], signed[i]), makeQuery("unsigned_DS", unsigned[i], unsigned[i]), makeQuery("absent_A", negative[i], ""), makeQuery("below_cut_A", fmt.Sprintf("bench-%05d.%s", i, delegates[i+20000]), delegates[i+20000]))
	}
	used := map[string]bool{}
	for _, q := range queries {
		used[fmt.Sprintf("%s/%d", q.Name, q.Type)] = true
	}
	for i := 0; i < 2000; i++ {
		candidate := []Query{makeQuery("delegation_A", delegates[i+50000], delegates[i+50000]), makeQuery("signed_DS", signed[i+20000], signed[i+20000]), makeQuery("unsigned_DS", unsigned[i+20000], unsigned[i+20000]), makeQuery("absent_A", negative[i+20000], ""), makeQuery("below_cut_A", fmt.Sprintf("warm-%05d.%s", i, delegates[i+52000]), delegates[i+52000])}
		for _, q := range candidate {
			key := fmt.Sprintf("%s/%d", q.Name, q.Type)
			if used[key] {
				panic("warmup overlaps measured queries")
			}
			used[key] = true
			warmup = append(warmup, q)
		}
	}
	rng.Shuffle(len(queries), func(i, j int) { queries[i], queries[j] = queries[j], queries[i] })
	rng.Shuffle(len(warmup), func(i, j int) { warmup[i], warmup[j] = warmup[j], warmup[i] })
	writeQueries(filepath.Join(root, "queries.jsonl"), queries)
	writeQueries(filepath.Join(root, "warmup.jsonl"), warmup)
	paths := map[string]string{}
	for _, name := range []string{"selected_source.zone", "owner_roles.tsv", "negative_names.txt", "queries.jsonl", "warmup.jsonl"} {
		file, e := os.Open(filepath.Join(root, name))
		check(e)
		h := sha256.New()
		_, e = io.Copy(h, file)
		check(e)
		file.Close()
		paths[name] = hex.EncodeToString(h.Sum(nil))
	}
	save(filepath.Join(root, "WORKLOAD.json"), map[string]any{"status": "PASS", "seed": 20261114, "measured_queries": len(queries), "warmup_queries": len(warmup), "sampled_source_rows": rows, "sampled_owner_count": len(owners), "source_type_counts": counts, "per_class_queries": 20000, "class_weights": "five classes, each0.2; controlled balanced distribution, not observed Internet traffic", "files_sha256": paths})
}
func validate(q Query, response *dns.Msg) error {
	if !response.Response || response.Rcode != q.Rcode || response.Authoritative != q.AA {
		return fmt.Errorf("rcode/AA got %d/%t expected %d/%t", response.Rcode, response.Authoritative, q.Rcode, q.AA)
	}
	if len(response.Question) != 1 || !strings.EqualFold(response.Question[0].Name, q.Name) || response.Question[0].Qtype != q.Type {
		return fmt.Errorf("wrong question")
	}
	wanted := dns.TypeNS
	if q.Category == "signed_DS" {
		wanted = dns.TypeDS
	} else if q.Category == "unsigned_DS" || q.Category == "absent_A" {
		wanted = dns.TypeSOA
	}
	section := response.Ns
	if q.Section == "answer" {
		section = response.Answer
	} else if len(response.Answer) != 0 {
		return fmt.Errorf("unexpected nonempty answer")
	}
	records := []dns.RR{}
	for _, rr := range section {
		if rr.Header().Rrtype == wanted {
			records = append(records, rr)
		}
	}
	got := unique(records)
	if strings.Join(got, ",") != strings.Join(q.Expected, ",") {
		return fmt.Errorf("source RRset mismatch got%d expected%d", len(got), len(q.Expected))
	}
	return nil
}
func exchange(conn net.Conn, wire []byte, address string, buffer []byte) ([]byte, int64, int64, bool, error) {
	check(conn.SetDeadline(time.Now().Add(2 * time.Second)))
	start := time.Now()
	_, e := conn.Write(wire)
	if e != nil {
		return nil, time.Since(start).Nanoseconds(), 0, false, e
	}
	n, e := conn.Read(buffer)
	stop := time.Now()
	udp := stop.Sub(start).Nanoseconds()
	if e != nil {
		return nil, udp, udp, false, e
	}
	buffer = buffer[:n]
	truncated := len(buffer) >= 4 && buffer[2]&2 != 0
	if truncated {
		tcp, e := net.DialTimeout("tcp", address, 2*time.Second)
		if e != nil {
			return buffer, time.Since(start).Nanoseconds(), udp, true, e
		}
		defer tcp.Close()
		tcp.SetDeadline(time.Now().Add(2 * time.Second))
		packet := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		packet = append(packet, wire...)
		_, e = tcp.Write(packet)
		if e != nil {
			return buffer, time.Since(start).Nanoseconds(), udp, true, e
		}
		header := make([]byte, 2)
		_, e = io.ReadFull(tcp, header)
		if e != nil {
			return buffer, time.Since(start).Nanoseconds(), udp, true, e
		}
		buffer = make([]byte, binary.BigEndian.Uint16(header))
		_, e = io.ReadFull(tcp, buffer)
		stop = time.Now()
		if e != nil {
			return buffer, stop.Sub(start).Nanoseconds(), udp, true, e
		}
	}
	return buffer, stop.Sub(start).Nanoseconds(), udp, truncated, nil
}
func describe(values []int64) Sample {
	if len(values) == 0 {
		return Sample{}
	}
	sum := float64(0)
	for _, v := range values {
		sum += float64(v)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	quantile := func(p float64) float64 { return float64(values[int(p*float64(len(values)-1))]) / 1000 }
	return Sample{len(values), sum / float64(len(values)) / 1000, quantile(.5), quantile(.95), quantile(.99), float64(values[len(values)-1]) / 1000}
}
func run(path, address, out string) {
	queries := loadQueries(path)
	conn, e := net.Dial("udp", address)
	check(e)
	defer conn.Close()
	file, e := os.Create(out + ".raw.jsonl")
	check(e)
	defer file.Close()
	writer := bufio.NewWriterSize(file, 1<<20)
	values := map[string][]int64{}
	all := []int64{}
	errors, consecutive, tcpCount, completed := 0, 0, 0, 0
	errorExamples := []map[string]any{}
	started := time.Now()
	receiveBuffer := make([]byte, 65535)
	for i, q := range queries {
		message := new(dns.Msg)
		message.SetQuestion(q.Name, q.Type)
		message.Id = uint16((i*7919 + 20261) % 65536)
		message.RecursionDesired = false
		message.SetEdns0(1232, false)
		wire, e := message.Pack()
		check(e)
		responseWire, latency, udp, tcp, e := exchange(conn, wire, address, receiveBuffer)
		response := new(dns.Msg)
		if e == nil {
			e = response.Unpack(responseWire)
		}
		if e == nil && response.Id != message.Id {
			e = fmt.Errorf("transaction ID mismatch")
		}
		if e == nil {
			e = validate(q, response)
		}
		row := map[string]any{"index": i, "category": q.Category, "name": q.Name, "type": q.Type, "complete_rtt_ns": latency, "udp_rtt_ns": udp, "tcp_fallback": tcp, "request_wire_hex": hex.EncodeToString(wire), "response_wire_hex": hex.EncodeToString(responseWire), "ok": e == nil}
		if tcp {
			tcpCount++
		}
		if e != nil {
			errors++
			consecutive++
			row["error"] = e.Error()
			if len(errorExamples) < 20 {
				errorExamples = append(errorExamples, map[string]any{"index": i, "name": q.Name, "type": q.Type, "category": q.Category, "error": e.Error()})
			}
		} else {
			consecutive = 0
			values[q.Category] = append(values[q.Category], latency)
			all = append(all, latency)
		}
		encoded, e := json.Marshal(row)
		check(e)
		_, e = writer.Write(append(encoded, '\n'))
		check(e)
		completed++
		if completed%10000 == 0 {
			writer.Flush()
			fmt.Fprintf(os.Stderr, "queries %d/%d errors%d\n", completed, len(queries), errors)
		}
		if consecutive >= 20 {
			break
		}
	}
	check(writer.Flush())
	perClass := map[string]Sample{}
	for name, v := range values {
		perClass[name] = describe(v)
	}
	status := "PASS"
	if errors != 0 || completed != len(queries) {
		status = "FAILED_QUERY_CORRECTNESS_OR_COMPLETION"
	}
	save(out+".json", map[string]any{"status": status, "address": address, "query_file": path, "planned_queries": len(queries), "completed_queries": completed, "errors": errors, "tcp_fallbacks": tcpCount, "successful_only_rtt": describe(all), "per_class_successful_rtt": perClass, "error_examples": errorExamples, "elapsed_with_untimed_validation_seconds": time.Since(started).Seconds(), "scope": "one outstanding closed-loop query; arithmetic mean over prescribed balanced workload only; failed requests retained; no performance claim if status fails"})
	if status != "PASS" {
		os.Exit(2)
	}
}
func smoke(address, out string) {
	tests := []struct {
		name       string
		typ        uint16
		rcode      int
		aa         bool
		answerType uint16
	}{{"example.", dns.TypeSOA, 0, true, dns.TypeSOA}, {"signed.example.", dns.TypeA, 0, false, 0}, {"signed.example.", dns.TypeDS, 0, true, dns.TypeDS}, {"unsigned.example.", dns.TypeDS, 0, true, 0}, {"absent.example.", dns.TypeA, 3, true, 0}, {"child.signed.example.", dns.TypeA, 0, false, 0}, {"branch.example.", dns.TypeA, 0, true, 0}, {"foo.wild.example.", dns.TypeA, 0, true, dns.TypeA}, {"block.wild.example.", dns.TypeA, 0, true, 0}, {"opaque.example.", 65200, 0, true, 65200}, {"opaque.example.", dns.TypeAAAA, 0, true, 0}}
	results := []map[string]any{}
	failures := 0
	for _, test := range tests {
		q := new(dns.Msg)
		q.SetQuestion(test.name, test.typ)
		q.RecursionDesired = false
		q.SetEdns0(1232, false)
		response, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(q, address)
		entry := map[string]any{"name": test.name, "type": test.typ}
		okay := err == nil
		if err != nil {
			entry["error"] = err.Error()
		} else {
			entry["rcode"] = response.Rcode
			entry["aa"] = response.Authoritative
			entry["wire_text"] = response.String()
			okay = response.Rcode == test.rcode && response.Authoritative == test.aa
			found := test.answerType == 0
			for _, rr := range response.Answer {
				found = found || rr.Header().Rrtype == test.answerType
			}
			okay = okay && found
			if test.answerType == 0 {
				okay = okay && len(response.Answer) == 0
			}
		}
		entry["ok"] = okay
		if !okay {
			failures++
		}
		results = append(results, entry)
	}
	save(out, map[string]any{"status": map[bool]string{true: "PASS", false: "FAILED"}[failures == 0], "failures": failures, "cases": results})
	if failures > 0 {
		os.Exit(2)
	}
}
func main() {
	mode := flag.String("mode", "run", "prepare|run|smoke")
	root := flag.String("root", "", "workload directory")
	queries := flag.String("queries", "", "JSONL source-derived workload")
	address := flag.String("address", "127.0.0.1:25114", "DNS endpoint")
	out := flag.String("out", "", "result prefix")
	flag.Parse()
	switch *mode {
	case "prepare":
		prepare(*root)
	case "run":
		run(*queries, *address, *out)
	case "smoke":
		smoke(*address, *out)
	default:
		panic("unknown mode")
	}
}
