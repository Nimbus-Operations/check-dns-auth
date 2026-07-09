# Check DNS Authoritative

An Icinga/Nagios plugin that checks all authoritative nameservers for a
zone and reports on discrepancies between them.

It checks for:

   - servers that are unresponsive, lame (REFUSED, SERVFAIL, an upward
     referral, or some other non-answer), or that answer without the `AA`
     bit set (answering from cache, forwarding, etc.)
   - a matching NS set between the parent's delegation and the zone apex
   - matching apex NS sets across all of the zone's servers
   - matching serial numbers (with optional warning/critical thresholds on
     the spread)
   - the presence of CDS/CDNSKEY records (optional)

Every address (IPv6 and IPv4) of every nameserver is checked individually,
so a nameserver whose address family instances disagree, or which is only
partially reachable, is detected.  The set of servers checked is the
delegation NS set from the parent, plus any names given with `--ns`, plus
any additional names discovered in the apex NS sets returned by the servers
themselves.

## Behaviour

### Output

The plugin reports OK, WARNING, or CRITICAL depending on supplied arguments
and the current status of the zone being checked.

   - unresponsive, lame, or non-authoritative servers: CRITICAL
   - apex NS set does not match the delegation (plus any `--ns` names): WARNING
   - apex NS sets disagree between servers: CRITICAL
   - serial numbers disagree: CRITICAL by default; see the serial threshold
     options below
   - CDS/CDNSKEY present: OK unless `--cds warning` or `--cds critical` is
     given

Problem output names the offending servers (with their addresses) to give
an operator a starting point for troubleshooting.  Where servers disagree
with each other, each group of servers is reported with the answer it gave:

```
ZONE CRITICAL - serials disagree (spread 2): 2026070802 [ns1.example.com. (192.0.2.1), ns2.example.com. (192.0.2.2)]; 2026070800 [ns3.example.com. (192.0.2.3)]
```

Counts of each problem type are emitted as performance data for trending.

Failures obtaining supporting information (e.g. inability to retrieve the
NS set from the parent zone) result in an UNKNOWN return value and an
explanatory message.  For example:

```
ZONE UNKNOWN - No answer from ns1.example.com., ns2.example.com. querying parent NS set for example.org.
```

### Serial number thresholds

Serial spread is the largest distance between any two servers' serial
numbers, computed with RFC 1982 serial arithmetic.  By default any spread
at all is CRITICAL.  A threshold you set is the behaviour you get:

   - `--serial-warning N` alone: WARNING above a spread of N, never CRITICAL
   - `--serial-critical N` alone: CRITICAL above a spread of N
   - both: the usual two-tier thresholds

## Usage

```
check_dns_auth -z ZONE [options]
```

| Option | Description |
| ------ | ----------- |
| `-z`, `--zone ZONE` | Zone name to check (required). |
| `-n`, `--ns NAMESERVER` | Add a name server to the required NS set, in addition to the delegation NS set.  May be repeated. |
| `--no-parent` | Skip the parent delegation lookup; the required NS set is then only the `--ns` list (requires at least one `--ns`). |
| `-N`, `--no-ns-check` | Skip the NS set checks. |
| `-S`, `--no-serial-check` | Skip the serial number check. |
| `--serial-warning SPREAD` | WARNING if the serial spread exceeds SPREAD. |
| `--serial-critical SPREAD` | CRITICAL if the serial spread exceeds SPREAD. |
| `-c`, `--cds {warning,critical}` | Return this status if CDS or CDNSKEY records are present. |
| `-4`, `--ipv4` / `-6`, `--ipv6` | Only check the given address family (default: both). |
| `-t`, `--timeout SECONDS` | Timeout for each individual DNS query (default: 5). |
| `-v`, `--verbose` | Increase output verbosity (up to 3 times). |

# Acknowledgements

This is initially inspired by Duane Wessels's perl plugin `check_zone_auth`.
