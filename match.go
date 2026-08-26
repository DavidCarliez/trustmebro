package main

import (
	"net"
	"strconv"
	"strings"
)

// Query is the structured interpretation of a shimmed command invocation.
type Query struct {
	Command string
	Domain  string   // normalized: lowercase, no trailing dot
	QType   string   // upper-case RR type, default A
	Short   bool     // dig +short
	NoAll   bool     // dig +noall
	Answer  bool     // dig +answer
	Server  string   // @server / trailing server arg
	XRev    string   // dig -x <ip> reverse lookup input
	RawArgs []string // original argv (for args matching)
}

// rrTypes is the set of record types dig/nslookup/host understand.
var rrTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "DNAME": true, "MX": true,
	"NS": true, "PTR": true, "SOA": true, "SRV": true, "TXT": true,
	"CAA": true, "ANY": true, "HINFO": true, "NAPTR": true, "TLSA": true,
	"DS": true, "DNSKEY": true, "NSEC": true, "NSEC3": true, "LOC": true,
	"RP": true, "SSHFP": true, "CERT": true, "URI": true,
}

func isRRType(s string) bool { return rrTypes[strings.ToUpper(s)] }

func normType(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	if !isRRType(t) {
		if strings.HasPrefix(t, "TYPE") {
			return t
		}
		return ""
	}
	return t
}

func normDomain(s string) string {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	return d
}

// ParseQuery interprets argv for a shimmed command. It returns nil when the
// invocation cannot be parsed (interactive mode, no domain), which means the
// shim should pass through.
func ParseQuery(cmd string, args []string) *Query {
	switch cmd {
	case "dig":
		return parseDig(args)
	case "nslookup":
		return parseNslookup(args)
	case "host":
		return parseHost(args)
	default:
		// Unknown command: only args-glob rules can match, no domain parsing.
		return &Query{Command: cmd, RawArgs: args}
	}
}

func parseDig(args []string) *Query {
	q := &Query{Command: "dig", QType: "A", RawArgs: args}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "@"):
			q.Server = strings.TrimPrefix(a, "@")
		case a == "-x" && i+1 < len(args):
			q.XRev = args[i+1]
			i++
		case strings.HasPrefix(a, "-x") && len(a) > 2:
			q.XRev = a[2:]
		case a == "-t" && i+1 < len(args):
			if t := normType(args[i+1]); t != "" {
				q.QType = t
				i++
			}
		case strings.HasPrefix(a, "-t") && len(a) > 2:
			if t := normType(a[2:]); t != "" {
				q.QType = t
			}
		case a == "-q" && i+1 < len(args):
			pos = append(pos, args[i+1])
			i++
		case strings.HasPrefix(a, "-q") && len(a) > 2:
			pos = append(pos, a[2:])
		case a == "+short":
			q.Short = true
		case a == "+noall":
			q.NoAll = true
		case a == "+all":
			q.NoAll = false
			q.Answer = true
		case a == "+answer":
			q.Answer = true
		case strings.HasPrefix(a, "+"):
			// other display/query options: keep in RawArgs, ignore here
		default:
			pos = append(pos, a)
		}
	}

	if q.XRev != "" {
		q.QType = "PTR"
		if d := reverseDomain(q.XRev); d != "" {
			q.Domain = d
		}
	}

	// Positionals: [domain] [qtype] or [qtype] [domain].
	for _, p := range pos {
		if t := normType(p); t != "" && (q.QType == "A" || isRRType(q.Domain)) {
			q.QType = t
			continue
		}
		if q.Domain == "" {
			q.Domain = normDomain(p)
		}
	}
	return q
}

func parseNslookup(args []string) *Query {
	q := &Query{Command: "nslookup", QType: "A", RawArgs: args}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-":
			return nil // interactive mode reads stdin; cannot spoof
		case a == "-type" || a == "-query" || a == "-q":
			if i+1 < len(args) {
				if t := normType(args[i+1]); t != "" {
					q.QType = t
				}
				i++
			}
		case strings.HasPrefix(a, "-type=") || strings.HasPrefix(a, "-query=") || strings.HasPrefix(a, "-q="):
			if t := normType(a[strings.Index(a, "=")+1:]); t != "" {
				q.QType = t
			}
		case strings.HasPrefix(a, "-"):
			// other options (debug, port, ...)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return nil
	}
	q.Domain = normDomain(pos[0])
	if len(pos) > 1 {
		q.Server = pos[1]
	}
	return q
}

func parseHost(args []string) *Query {
	q := &Query{Command: "host", QType: "A", RawArgs: args}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" && i+1 < len(args):
			if t := normType(args[i+1]); t != "" {
				q.QType = t
			}
			i++
		case strings.HasPrefix(a, "-t") && len(a) > 2:
			if t := normType(a[2:]); t != "" {
				q.QType = t
			}
		case a == "-a":
			q.QType = "ANY"
		case strings.HasPrefix(a, "-"):
			// -C -c -d -l -v -4 -6 -T ...: ignore
		default:
			q.Domain = normDomain(a)
		}
	}
	if q.Domain == "" {
		return nil
	}
	return q
}

// reverseDomain converts an IP to the in-addr.arpa / ip6.arpa reverse name.
func reverseDomain(ip string) string {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		parts := []string{strconv.Itoa(int(v4[3])), strconv.Itoa(int(v4[2])), strconv.Itoa(int(v4[1])), strconv.Itoa(int(v4[0]))}
		return strings.Join(parts, ".") + ".in-addr.arpa"
	}
	var b []string
	for i := len(p) - 1; i >= 0; i-- {
		b = append(b, string(rune('0'+p[i]&0x0f)), string(rune('0'+p[i]>>4)))
	}
	return strings.Join(b, ".") + ".ip6.arpa"
}

// matches reports whether the rule matches the query.
func (r *Rule) matches(q *Query) bool {
	if r.Command != "" && r.Command != "*" && r.Command != q.Command {
		return false
	}
	if r.Match.QType != "" && !strings.EqualFold(r.Match.QType, q.QType) {
		return false
	}
	if r.Match.Domain != "" {
		if q.Domain == "" || !globRegexpMatch(r.Match.Domain, q.Domain) {
			return false
		}
	}
	if r.Match.DomainRe != "" {
		if q.Domain == "" || r.domainRe == nil || !r.domainRe.MatchString(q.Domain) {
			return false
		}
	}
	for _, re := range r.globRe {
		hit := false
		for _, a := range q.RawArgs {
			if re.MatchString(a) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func globRegexpMatch(glob, s string) bool {
	re, err := globRegexp(glob)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// matchRule returns the first rule matching q, or nil.
func matchRule(cfg *Config, q *Query) *Rule {
	if q == nil {
		return nil
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].matches(q) {
			return &cfg.Rules[i]
		}
	}
	return nil
}

// modeFor resolves the effective action of a rule.
func modeFor(r *Rule) string {
	if r == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(r.Action)) {
	case "spoof", "rewrite", "passthrough", "reject":
		return strings.ToLower(strings.TrimSpace(r.Action))
	}
	if r.Output != "" || r.Stderr != "" || r.Exit != nil || len(r.Records) > 0 {
		return "spoof"
	}
	if len(r.Rewrite) > 0 {
		return "rewrite"
	}
	return "passthrough"
}
