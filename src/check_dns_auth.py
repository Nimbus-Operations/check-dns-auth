# ==============================================================================
#  Copyright © 2022 Matthew Pounsett <matt@NimbusOps.com>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# ==============================================================================
"""
An Icinga/Nagios-compatible plugin that checks authoritative name servers
for a zone to ensure they have synchronized NS RR sets and serial numbers.
It can optionally require a particular NS RR set and/or alert on the presence of
CDS/CDNSKEY records.
"""

import argparse
import inspect
import logging
import random
import sys
from dataclasses import dataclass
from typing import Optional

import dns.message
import dns.resolver
import nagiosplugin

__version__ = "0.0.1"

_LOG = logging.getLogger('nagiosplugin')


@dataclass
class DNSServer:
    """Dataclass object to track information about each name server"""
    # Did this name server answer a query at all?
    responds: bool = False
    # Does this name server answer authoritatively for the zone?
    authoritative: bool = False
    # Current serial reported by this name server
    serial: Optional[int] = None
    # The apex NS set returned by this name server
    ns_names: Optional[list[dns.name.Name]] = None
    # Does this server have CDS or CDNSKEY records at the apex?
    cds_set: Optional[list[dns.rdata.Rdata]] = None
    cdnskey_set: Optional[list[dns.rdata.Rdata]] = None


def get_addresses(host: dns.name.Name) -> list[str]:
    """Given a hostname, resolve and return all A and AAAA addresses for it."""
    results = []
    resolver = dns.resolver.Resolver(configure=True)
    for rr_type in (dns.rdatatype.AAAA, dns.rdatatype.A):
        answer = resolver.resolve(host.to_text(), rr_type)
        addresses = [rr.address for rr in answer.response.get_rrset(dns.message.ANSWER, host,
                                                                    dns.rdataclass.IN, rr_type)]
        results.extend(addresses)
    return results


def get_ns_set_from_servers(qname: dns.name.Name,
                            servers: list[dns.name.Name | str],
                            allow_authority: bool = False) -> Optional[list[dns.name.Name]]:
    """
    Query specific servers with RD=0 until an NS set is obtained.

    Will query servers (in random order if more than one server is supplied) until an NS set for
    the supplied zone is returned in the Answer section of the response.

    Args:
        qname (dns.name.Name):
            The apex name of the zone.
        servers (list[dns.name.Name | str]):
            A list of dns.name.Name objects or string representations of IP addresses to check.
        allow_authority (bool, optional):
            If True, then an NS set in the Authority section of a DNS response is accepted.
            Defaults to False.

    Returns:
        A list of dns.name.Name objects, or None if no NS set was found.
    """
    server_addresses = []
    for host in servers:
        if isinstance(host, dns.name.Name):
            server_addresses.extend(get_addresses(host))
        else:
            server_addresses.append(host)

    sections = [dns.message.ANSWER]
    if allow_authority:
        sections.append(dns.message.AUTHORITY)

    query = dns.message.make_query(qname, dns.rdatatype.NS, flags=0)
    # query in random order until we get an answer
    for server in sorted(server_addresses, key=lambda _: random.random()):
        response, used_tcp = dns.query.udp_with_fallback(query, server)
        for section in sections:
            ns_rr_set = response.get_rrset(section, qname,
                                          dns.rdataclass.IN, dns.rdatatype.NS)
            if ns_rr_set:
                return [rr.target for rr in ns_rr_set]
    return None


def get_delegation_ns_set(zone: dns.name.Name) -> Optional[list[dns.name.Name]]:
    """Returns the zone's delegation NS set from a zone's parent.

    This function looks up the name of the zone's parent, gets the NS set for the parent zone,
    then initiates queries to the parent's name servers for the NS set of the child zone.

    Args:
        zone (dns.name.Name):
            The apex name of the zone we need the NS set for.

    Returns: a list of dns.name.Name objects, or None if no NS set was found.
    """
    # Get the name of the child zone's parent, and query for the parent's NS records.
    resolver = dns.resolver.Resolver(configure=True)
    answer = resolver.resolve(zone.parent().to_text(), 'NS')
    # Extract a list of the parent's name server names.
    ns_rr_set = answer.response.get_rrset(dns.message.ANSWER, zone,
                                          dns.rdataclass.IN, dns.rdatatype.NS)
    parent_zone_ns_names: list[dns.name.Name] = [rr.target for rr in ns_rr_set]
    if not parent_zone_ns_names:
        return None

    # Now query one (or more) of these until we get the parent's delegation NS set
    # for the child zone in question.
    return get_ns_set_from_servers(zone, parent_zone_ns_names,
                                   allow_authority=True)


def query_nameserver(qname: dns.name.Name,
                     server: dns.name.Name,
                     rr_type: dns.rdatatype) -> Optional[dns.message.Message]:
    """Query a nameserver and return the response.

        Args:
            qname (dns.name.Name):
                The domain name to query about.
            server (dns.name.Name):
                The DNS server to query.
            rr_type (dns.rdatatype):
                The DNS rtype to query.

        Returns:
            A dns.message.Message, or None if no response was found.
        """
    for address in get_addresses(server):
        _LOG.debug(f"Querying nameserver {address} for {qname}/{rr_type.name}")
        query = dns.message.make_query(qname, rr_type)
        # discard the TCP connection boolean
        (response, _) = dns.query.udp_with_fallback(query, address)
        if response:
            return response
    return None


def update_server_data(zone: dns.name.Name,
                       server: dns.name.Name,
                       data: dict[dns.name.Name, DNSServer]) -> None:
    """Collect data about a supplied server and add or update its entry in the data dictionary.

    Args:
        zone (dns.name.Name):
            The DNS zone being checked.
        server (dns.name.Name):
            The DNS server to query.
        data (dict[dns.name.Name, DNSServer]):
            The data dictionary to add data to.  The dictionary maps name server names to their
            corresponding DNSServer objects.
    """
    if server not in data:
        data[server] = DNSServer()
    response = query_nameserver(zone, server, dns.rdatatype.SOA)
    if not response:
        return
    data[server].responds = True
    soa = response.get_rrset(dns.message.ANSWER, zone,
                             dns.rdataclass.IN, dns.rdatatype.SOA)
    # I considered returning from the function here if `soa` is None.  If we're expecting this
    # server to be authoritative, and it's not returning an SOA record, then the delegation is
    # probably lame.  But we might as well just record the result and test the rest of the
    # things, just in case.
    data[server].serial = soa[0].serial if soa else None
    if dns.flags.AA in response.flags:
        data[server].authoritative = True

    # Some implementations will include the NS set in the AUTHORITY section of an AA response,
    # so take advantage of that if it's available.
    ns_set = response.get_rrset(dns.message.AUTHORITY, zone,
                                dns.rdataclass.IN, dns.rdatatype.NS)
    data[server].ns_names = [rr.target for rr in ns_set]

    # If there was no NS set in the AUTHORITY section of the SOA query, then query directly for it.
    if not data[server].ns_names:
        response = query_nameserver(zone, server, dns.rdatatype.NS)
        ns_set = response.get_rrset(dns.message.ANSWER, zone,
                                    dns.rdataclass.IN, dns.rdatatype.NS)
        data[server].ns_names = [rr.target for rr in ns_set]

    # And now check for CDS/CDNSKEY records.
    response = query_nameserver(zone, server, dns.rdatatype.CDS)
    data[server].cds_set = response.get_rrset(dns.message.ANSWER, zone,
                                              dns.rdataclass.IN, dns.rdatatype.CDS)
    response = query_nameserver(zone, server, dns.rdatatype.CDNSKEY)
    data[server].cdnskey_set = response.get_rrset(dns.message.ANSWER, zone,
                                                  dns.rdataclass.IN, dns.rdatatype.CDNSKEY)




class Zone(nagiosplugin.Resource):
    """nagiosplugin.Resource representation fo a DNS zone"""
    def __init__(self, args: argparse.Namespace):
        self.require_ns = [dns.name.from_text(ns) for ns in args.ns]
        self.zone = dns.name.from_text(args.zone)
        self.check_cds: bool = args.cds

    def probe(self) -> None:
        # The data variable maps a name server name to its associated DNSServer dataclass object.
        data: dict[dns.name.Name, DNSServer] = {}
        # Only going to do this once.  We're not here to test the parent, so we'll assume that
        # the parent has a consistent delegation NS set for the child.
        parent_ns_set = set(get_delegation_ns_set(self.zone))

        # If the parent NS set is empty, there isn't anything else we can do.


        # This will hold our list of every name server name discovered at the apex.  It should be
        # consistent across all the child zone's name servers, but we might add to it as we query
        # name servers.
        apex_ns_set = set()

        # Loop through every name server in the delegation NS set: query it for the key bits of
        # information about the zone and construct a DNSServer object to record its vitals.
        for server_name in parent_ns_set:
            update_server_data(self.zone, server_name, data)
            # If we discovered any new name server names, add them to the NS set.
            if data[server_name].responds is True and data[server_name].ns_names:
                apex_ns_set.update(set(data[server_name].ns_names))

        # Having checked all the servers listed in the parent NS set, look at any new server
        # names discovered from the apex ns sets returned by those servers (names in apex_ns_set
        # that are not in the keys of the data dictionary).
        #
        # We'll use a while loop because the test for whether we need to continue looping will be
        # whether anything in apex_ns_set is not in our data, and we might modify apex_ns_set
        # inside the loop.
        while apex_ns_set.difference(set(data.keys())):
            scan_ns_set = apex_ns_set.copy()
            for server_name in scan_ns_set:
                if server_name in data:
                    # We already knew about this one, move on.
                    continue
                # This is new.
                update_server_data(self.zone, server_name, data)
                if data[server_name].responds is True and data[server_name].ns_names:
                    apex_ns_set.update(set(data[server_name].ns_names))

        # Examine the results to start constructing metrics.



def parse_args(args=None) -> argparse.Namespace:
    """Parse command line arguments and return a Namespace object."""
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=inspect.cleandoc(
            """
            Check that the NS RR set at the apex of the supplied zone matches 
            the parent, and that each name server has the same NS RR set, 
            and that the serial numbers are consistent.
            
            Optionally match the NS RR set to the list supplied on the command
            line, and/or alert on the presence of CDS/CDNSKEY records.
            """
        )
    )
    parser.add_argument(
        '-z', '--zone',
        metavar='ZONE NAME',
        required=True,
        help='Zone name to check.',
    )
    parser.add_argument(
        '-n', '--ns',
        metavar='NAMESERVER',
        action='append',
        default=list(),
        help="Add a name server to the required NS RR set.  May be specified multiple times.",
    )
    parser.add_argument(
        '--no-parent',
        action='store_true',
        help=(
            "Skip obtaining the delegation NS set from the parent zone "
            "(requires at least one --ns)"
        ),
    )
    parser.add_argument(
        '-N', '--no-ns-check',
        action='store_true',
        help="Skip checking for a matching apex NS set.",
    )
    parser.add_argument(
        '-S', '--no-serial-check',
        action='store_true',
        help="Skip checking for a matching SOA serial number.",
    )
    parser.add_argument(
        '-s', '--serial-error',
        metavar='MARGIN',
        type=int,
        help="If the SOA serial number differs by MARGIN (integer) or less it is not an error.",
    )
    parser.add_argument(
        '-c', '--cds',
        choices=['warning', 'critical'],
        default=None,
        help="If CDS or CDNSKEY records are present in the zone, return the requested status.",
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help="Increase output verbosity (use up to 3 times).",
    )
    return parser.parse_args(args)


def setup_check(args: argparse.Namespace) -> None:
    """Set up and run the actual check."""
    contexts = [
        nagiosplugin.ScalarContext('Parent RR set', '0', ''),
        nagiosplugin.ScalarContext('Apex RR set', '', '0'),
        nagiosplugin.ScalarContext('Serial', '0', '')
    ]
    if args.cds:
        contexts.append(
            nagiosplugin.ScalarContext('cds',
                                       '0' if args.cds == 'warning' else '',
                                       '0' if args.cds == 'critical' else ''
                                       )
        )
    check = nagiosplugin.Check(Zone(args), *contexts)
    check.main(verbose=args.verbose)


@nagiosplugin.guarded(verbose=0)
def main() -> None:
    """Run the check-dns-auth script.  This is the main entrypoint."""
    args = parse_args()
    setup_check(args)

