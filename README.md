# Check DNS Authoritative

An Icinga/Nagios plugin that checks that all authoritative nameservers for a
zone have the same NS RRset and the same serial number.  It can also
optionally accept an NS RRset on the commandline to enforce, and/or alert on
the presence of CDS/CDNSKEY records.

## Usage

# Acknowledgements

This is heavily inspired by Duane Wessels's perl plugin `check_zone_auth`.
