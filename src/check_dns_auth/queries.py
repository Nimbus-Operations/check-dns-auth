# ==============================================================================
#  Copyright © 2022-2026 Matthew Pounsett <matt@NimbusOps.com>
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
"""The DNS I/O layer: resolving, querying, and classifying name servers."""

import logging
import random
from typing import Optional

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import nagiosplugin

from check_dns_auth.model import ServerResult, ServerStatus

_LOG = logging.getLogger('nagiosplugin')

# The address family rdatatypes (AAAA/A) to use when resolving server names.
Families = tuple[dns.rdatatype.RdataType, ...]

ALL_FAMILIES: Families = (dns.rdatatype.AAAA, dns.rdatatype.A)


def resolve_addresses(host: dns.name.Name, lifetime: float,
                      families: Families = ALL_FAMILIES) -> list[str]:
    """Resolve the AAAA and/or A addresses for a hostname.

    A hostname missing one of the address types is normal and not an error;
    a hostname that resolves to nothing returns an empty list.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    addresses: list[str] = []
    for rr_type in families:
        try:
            addresses.extend(rr.address for rr in resolver.resolve(host, rr_type))
        except dns.exception.DNSException as err:
            _LOG.debug("no %s answer for %s: %s", rr_type.name, host, err)
    return addresses


def query(qname: dns.name.Name,
          address: str,
          rr_type: dns.rdatatype.RdataType,
          timeout: float) -> Optional[dns.message.Message]:
    """Send a single non-recursive (RD=0) query to one address.

    Returns the response Message, or None on timeout or network error.
    """
    _LOG.debug("querying %s for %s/%s", address, qname, rr_type.name)
    request = dns.message.make_query(qname, rr_type, flags=0)
    try:
        response, _ = dns.query.udp_with_fallback(request, address, timeout=timeout)
    except (dns.exception.DNSException, OSError) as err:
        _LOG.debug("no response from %s: %s", address, err)
        return None
    return response


def _is_upward_referral(response: dns.message.Message, zone: dns.name.Name) -> bool:
    """Report whether the response refers to some zone other than the target."""
    return any(rrset.rdtype == dns.rdatatype.NS and rrset.name != zone
               for rrset in response.authority)


def check_address(zone: dns.name.Name,
                  name: dns.name.Name,
                  address: str,
                  timeout: float,
                  check_cds: bool) -> ServerResult:
    """Query one address of one name server and classify the instance."""
    response = query(zone, address, dns.rdatatype.SOA, timeout)
    if response is None:
        return ServerResult(name, address, ServerStatus.UNRESPONSIVE, 'no response')
    rcode = response.rcode()
    if rcode != dns.rcode.NOERROR:
        return ServerResult(name, address, ServerStatus.LAME, dns.rcode.to_text(rcode))
    soa = response.get_rrset(dns.message.ANSWER, zone,
                             dns.rdataclass.IN, dns.rdatatype.SOA)
    if soa is None:
        detail = ('upward referral' if _is_upward_referral(response, zone)
                  else 'empty answer')
        return ServerResult(name, address, ServerStatus.LAME, detail)
    if not response.flags & dns.flags.AA:
        return ServerResult(name, address, ServerStatus.NON_AUTHORITATIVE,
                            serial=soa[0].serial)

    result = ServerResult(name, address, ServerStatus.HEALTHY, serial=soa[0].serial)

    # Some implementations include the apex NS set in the AUTHORITY section of
    # an authoritative SOA response; otherwise query for it directly.
    ns_set = response.get_rrset(dns.message.AUTHORITY, zone,
                                dns.rdataclass.IN, dns.rdatatype.NS)
    if ns_set is None:
        ns_response = query(zone, address, dns.rdatatype.NS, timeout)
        if ns_response is not None:
            ns_set = ns_response.get_rrset(dns.message.ANSWER, zone,
                                           dns.rdataclass.IN, dns.rdatatype.NS)
    if ns_set is not None:
        result.ns_names = frozenset(rr.target for rr in ns_set)

    if check_cds:
        for rr_type, attr in ((dns.rdatatype.CDS, 'cds'),
                              (dns.rdatatype.CDNSKEY, 'cdnskey')):
            cds_response = query(zone, address, rr_type, timeout)
            if cds_response and cds_response.get_rrset(
                    dns.message.ANSWER, zone, dns.rdataclass.IN, rr_type):
                setattr(result, attr, True)
    return result


def check_server(zone: dns.name.Name,
                 name: dns.name.Name,
                 timeout: float,
                 check_cds: bool,
                 families: Families = ALL_FAMILIES) -> list[ServerResult]:
    """Query every address of one name server, returning one result each."""
    addresses = resolve_addresses(name, timeout, families)
    if not addresses:
        return [ServerResult(name, None, ServerStatus.UNRESPONSIVE,
                             'hostname did not resolve')]
    return [check_address(zone, name, address, timeout, check_cds)
            for address in addresses]


def get_delegation_ns_set(zone: dns.name.Name,
                          timeout: float,
                          families: Families = ALL_FAMILIES) -> set[dns.name.Name]:
    """Return the zone's delegation NS set, obtained from its parent zone.

    Finds the enclosing zone of the target zone's parent name, then queries
    that zone's servers (in random order) until one returns an NS set for the
    target zone in either the answer or authority section.

    Raises nagiosplugin.CheckError (reported as UNKNOWN) if the parent zone or
    the delegation NS set cannot be obtained.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        parent_zone = dns.resolver.zone_for_name(zone.parent(), resolver=resolver)
        parent_servers = [rr.target for rr in resolver.resolve(parent_zone, 'NS')]
    except dns.exception.DNSException as err:
        raise nagiosplugin.CheckError(
            f"Unable to find parent zone name servers for {zone}: {err}") from err

    random.shuffle(parent_servers)
    rcodes = set()
    for server in parent_servers:
        for address in resolve_addresses(server, timeout, families):
            response = query(zone, address, dns.rdatatype.NS, timeout)
            if response is None:
                continue
            rcodes.add(response.rcode())
            for section in (dns.message.ANSWER, dns.message.AUTHORITY):
                ns_set = response.get_rrset(section, zone,
                                            dns.rdataclass.IN, dns.rdatatype.NS)
                if ns_set:
                    return {rr.target for rr in ns_set}
    if rcodes:
        rcode_text = '/'.join(sorted(dns.rcode.to_text(rcode) for rcode in rcodes))
        raise nagiosplugin.CheckError(
            f"No delegation NS set for {zone} found in parent zone "
            f"{parent_zone} ({rcode_text})")
    server_text = ', '.join(sorted(str(server) for server in parent_servers))
    raise nagiosplugin.CheckError(
        f"No answer from {server_text} querying parent NS set for {zone}")
