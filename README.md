# Check DNS Authoritative

An Icinga/Nagios plugin that checks that all authoritative nameservers for a
zone and reports on discrepencies between them.

It checks for:

   - a matching NS set
   - matching serial numbers (optional, with an optional allowed margin of
     error)
   - the presence of CDS/CDNSKEY records

The plugin can optionally take a list of name server names to use as the NS
set to match, instead of obtaining the initial set from the parent zone.

## Behaviour

### Output

The plugin will report OK, WARNING, or CRITICAL depending on supplied
arguments and the current status of the zone being checked.

Failures obtaining supporting information (e.g. inability to retrieve the NS
set from the parent zone) will result in an UNKNOWN return value and an
explanatory message.  For example:

```
UNKNOWN: No answer from ns1.example.com, ns2.example.com querying parent NS set.
```

# Acknowledgements

This is heavily inspired by Duane Wessels's perl plugin `check_zone_auth`.
