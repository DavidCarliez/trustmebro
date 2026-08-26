package main

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"time"
)

const digVersion = "9.18.27-1-arch"

// defaultRecords are the built-in answers used when a rule gives none for a
// type. TEST-NET / documentation ranges so nothing collides with real hosts.
var defaultRecords = map[string][]string{
	"A":     {"203.0.113.10"},
	"AAAA":  {"2001:db8::10"},
	"CNAME": {"target.example.net."},
	"MX":    {"10 mail.example.net."},
	"NS":    {"ns1.example.net."},
	"TXT":   {`"trustmebro"`},
	"SOA":   {"ns1.example.net. hostmaster.example.net. 2026082601 7200 3600 1209600 300"},
	"PTR":   {"host.example.net."},
	"CAA":   {`0 issue "letsencrypt.org"`},
}

const recordOrder = "A AAAA CNAME MX NS TXT SOA PTR CAA"

// recordsFor returns the answer values for a qtype, merging rule records
// over defaults.
func recordsFor(r *Rule, qtype string) []string {
	if qtype == "" {
		qtype = "A"
	}
	if r != nil {
		if v, ok := r.Records[qtype]; ok {
			return v
		}
	}
	return defaultRecords[qtype]
}

// typedRec pairs an RR type with one answer value.
type typedRec struct{ Type, Value string }

// recordsTyped returns type+value pairs for a qtype, merging rule records
// over defaults. ANY flattens all types in a stable order, each tagged with
// its own type.
func recordsTyped(r *Rule, qtype string) []typedRec {
	if qtype == "" {
		qtype = "A"
	}
	if qtype == "ANY" {
		var out []typedRec
		for _, t := range strings.Fields(recordOrder) {
			for _, v := range recordsFor(r, t) {
				out = append(out, typedRec{t, v})
			}
		}
		return out
	}
	var out []typedRec
	for _, v := range recordsFor(r, qtype) {
		out = append(out, typedRec{qtype, v})
	}
	return out
}

// generate produces the spoofed stdout, stderr, and exit code for a query.
func generate(q *Query, r *Rule) (string, string, int) {
	code := 0
	if r != nil && r.Exit != nil {
		code = *r.Exit
	}
	if r != nil && r.Output != "" {
		return r.Output, r.Stderr, code
	}
	switch q.Command {
	case "dig":
		return digGen(q, r), r.Stderr, code
	case "nslookup":
		return nsGen(q, r), r.Stderr, code
	case "host":
		return hostGen(q, r), r.Stderr, code
	}
	return "", r.Stderr, code
}

func digGen(q *Query, r *Rule) string {
	qtype := q.QType
	if qtype == "" {
		qtype = "A"
	}
	recs := recordsTyped(r, qtype)
	domain := q.Domain

	if q.Short {
		var b strings.Builder
		for _, v := range recs {
			b.WriteString(v.Value)
			b.WriteByte('\n')
		}
		return b.String()
	}
	if q.NoAll {
		// +noall +answer: bare answer records, no headers.
		var b strings.Builder
		for _, v := range recs {
			fmt.Fprintf(&b, "%s.\t\t%d\tIN\t%s\t%s\n", domain, 300, v.Type, v.Value)
		}
		return b.String()
	}

	var b strings.Builder
	id := rand.IntN(50000) + 10000
	fmt.Fprintf(&b, "; <<>> DiG %s <<>> %s %s\n", digVersion, domain, qtype)
	fmt.Fprintf(&b, ";; global options: +cmd\n")
	fmt.Fprintf(&b, ";; Got answer:\n")
	fmt.Fprintf(&b, ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %d\n", id)
	fmt.Fprintf(&b, ";; flags: qr rd ra; QUERY: 1, ANSWER: %d, AUTHORITY: 0, ADDITIONAL: 1\n", len(recs))
	b.WriteString("\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 1232\n")
	fmt.Fprintf(&b, ";; QUESTION SECTION:\n;%s.\t\t\tIN\t%s\n\n", domain, qtype)
	b.WriteString(";; ANSWER SECTION:\n")
	for _, v := range recs {
		fmt.Fprintf(&b, "%s.\t\t%d\tIN\t%s\t%s\n", domain, 300, v.Type, v.Value)
	}
	b.WriteString("\n")
	server := q.Server
	if server == "" {
		server = "127.0.0.53"
	}
	size := 96
	for _, v := range recs {
		size += len(v.Value) + 20
	}
	fmt.Fprintf(&b, ";; Query time: %d msec\n", rand.IntN(56)+5)
	fmt.Fprintf(&b, ";; SERVER: %s#53(%s) (UDP)\n", server, server)
	fmt.Fprintf(&b, ";; WHEN: %s\n", time.Now().Format("Mon Jan 2 15:04:05 2006"))
	fmt.Fprintf(&b, ";; MSG SIZE  rcvd: %d\n", size)
	return b.String()
}

func nsGen(q *Query, r *Rule) string {
	qtype := q.QType
	if qtype == "" {
		qtype = "A"
	}
	recs := recordsTyped(r, qtype)
	server := q.Server
	if server == "" {
		server = "127.0.0.53"
	}
	domain := q.Domain

	var b strings.Builder
	fmt.Fprintf(&b, "Server:\t\t%s\n", server)
	fmt.Fprintf(&b, "Address:\t%s#53\n\n", server)
	b.WriteString("Non-authoritative answer:\n")
	namePrinted := false
	for _, v := range recs {
		switch v.Type {
		case "A":
			if !namePrinted {
				fmt.Fprintf(&b, "Name:\t%s\n", domain)
				namePrinted = true
			}
			fmt.Fprintf(&b, "Address: %s\n", v.Value)
		case "TXT":
			fmt.Fprintf(&b, "%s\ttext = %s\n", domain, v.Value)
		case "MX":
			fmt.Fprintf(&b, "%s\tmail exchanger = %s\n", domain, v.Value)
		case "NS":
			fmt.Fprintf(&b, "%s\tnameserver = %s\n", domain, v.Value)
		case "CNAME":
			fmt.Fprintf(&b, "%s\tcanonical name = %s\n", domain, v.Value)
		default:
			fmt.Fprintf(&b, "%s\t%s = %s\n", domain, strings.ToLower(v.Type), v.Value)
		}
	}
	return b.String()
}

func hostGen(q *Query, r *Rule) string {
	qtype := q.QType
	if qtype == "" {
		qtype = "A"
	}
	recs := recordsTyped(r, qtype)
	domain := q.Domain
	var b strings.Builder
	for _, v := range recs {
		switch v.Type {
		case "A":
			fmt.Fprintf(&b, "%s has address %s\n", domain, v.Value)
		case "AAAA":
			fmt.Fprintf(&b, "%s has IPv6 address %s\n", domain, v.Value)
		case "TXT":
			fmt.Fprintf(&b, "%s descriptive text %s\n", domain, v.Value)
		case "MX":
			fmt.Fprintf(&b, "%s mail is handled by %s\n", domain, v.Value)
		case "NS":
			fmt.Fprintf(&b, "%s name server %s\n", domain, v.Value)
		case "CNAME":
			fmt.Fprintf(&b, "%s is an alias for %s\n", domain, v.Value)
		case "PTR":
			fmt.Fprintf(&b, "%s domain name pointer %s\n", domain, v.Value)
		case "SOA":
			fmt.Fprintf(&b, "%s has SOA record %s\n", domain, v.Value)
		case "CAA":
			fmt.Fprintf(&b, "%s has CAA record %s\n", domain, v.Value)
		default:
			fmt.Fprintf(&b, "%s has %s record %s\n", domain, strings.ToLower(v.Type), v.Value)
		}
	}
	return b.String()
}

// applyRewrites runs ordered transforms over real command output.
func applyRewrites(ops []RewriteOp, s string) string {
	for _, op := range ops {
		switch {
		case op.Regex != "":
			re := op.compiled
			if re == nil {
				re, _ = regexp.Compile(op.Regex)
			}
			if re != nil {
				s = re.ReplaceAllString(s, op.Replace)
			}
		case op.Find != "":
			s = strings.ReplaceAll(s, op.Find, op.Replace)
		}
	}
	return s
}
