# ==============================================================================
#  Copyright © 2025 Matthew Pounsett <matt@NimbusOps.com>
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
"""Tests for the DNS query and classification layer."""
import unittest
from unittest.mock import Mock, patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import nagiosplugin

from check_dns_auth.model import ServerStatus
from check_dns_auth.queries import (check_address, check_server,
                                    get_delegation_ns_set, resolve_addresses)

ZONE = dns.name.from_text('example.com.')
NS1 = dns.name.from_text('ns1.example.com.')


def make_response(rr_type=dns.rdatatype.SOA,
                  rcode=dns.rcode.NOERROR,
                  aa=True,
                  answer=None,
                  authority=None) -> dns.message.Message:
    """Build a DNS response message for the test zone."""
    request = dns.message.make_query(ZONE, rr_type, flags=0)
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    if aa:
        response.flags |= dns.flags.AA
    # Add rrsets via find_rrset so the message's internal index sees them,
    # as it would for a response parsed off the wire.
    for section, rrset in ((response.answer, answer),
                           (response.authority, authority)):
        if rrset:
            response.find_rrset(section, rrset.name, rrset.rdclass,
                                rrset.rdtype, create=True).update(rrset)
    return response


def soa_rrset(serial=100):
    """An SOA answer rrset for the test zone."""
    return dns.rrset.from_text(
        'example.com.', 300, 'IN', 'SOA',
        f'ns1.example.com. hostmaster.example.com. {serial} 3600 900 604800 300')


def ns_rrset(name='example.com.'):
    """An NS rrset, at the zone apex by default."""
    return dns.rrset.from_text(name, 300, 'IN', 'NS',
                               'ns1.example.com.', 'ns2.example.com.')


class TestResolveAddresses(unittest.TestCase):
    """Tests for the resolve_addresses function."""

    @patch('dns.resolver.Resolver.resolve')
    def test_both_families(self, mock_resolve) -> None:
        """AAAA and A answers are combined, v6 first."""
        mock_resolve.side_effect = [
            [Mock(address='2001:db8::1')],
            [Mock(address='192.0.2.1')],
        ]
        self.assertEqual(resolve_addresses(NS1, 5.0),
                         ['2001:db8::1', '192.0.2.1'])

    @patch('dns.resolver.Resolver.resolve')
    def test_missing_aaaa_is_not_an_error(self, mock_resolve) -> None:
        """A hostname with only A records still resolves."""
        mock_resolve.side_effect = [
            dns.resolver.NoAnswer(),
            [Mock(address='192.0.2.1')],
        ]
        self.assertEqual(resolve_addresses(NS1, 5.0), ['192.0.2.1'])

    @patch('dns.resolver.Resolver.resolve')
    def test_nothing_resolves(self, mock_resolve) -> None:
        """A hostname that resolves to nothing returns an empty list."""
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        self.assertEqual(resolve_addresses(NS1, 5.0), [])

    @patch('dns.resolver.Resolver.resolve')
    def test_family_restriction(self, mock_resolve) -> None:
        """Only the requested address families are resolved."""
        mock_resolve.return_value = [Mock(address='192.0.2.1')]
        addresses = resolve_addresses(NS1, 5.0, (dns.rdatatype.A,))
        self.assertEqual(addresses, ['192.0.2.1'])
        mock_resolve.assert_called_once_with(NS1, dns.rdatatype.A)


class TestCheckAddress(unittest.TestCase):
    """Classification tests for the check_address function."""

    def check(self, check_cds=False):
        """Run check_address against the patched query function."""
        return check_address(ZONE, NS1, '192.0.2.1', 5.0, check_cds)

    @patch('check_dns_auth.queries.query')
    def test_unresponsive(self, mock_query) -> None:
        """No response classifies as UNRESPONSIVE."""
        mock_query.return_value = None
        result = self.check()
        self.assertIs(result.status, ServerStatus.UNRESPONSIVE)

    @patch('check_dns_auth.queries.query')
    def test_refused_is_lame(self, mock_query) -> None:
        """A REFUSED response classifies as LAME with the rcode as detail."""
        mock_query.return_value = make_response(rcode=dns.rcode.REFUSED,
                                                aa=False)
        result = self.check()
        self.assertIs(result.status, ServerStatus.LAME)
        self.assertEqual(result.detail, 'REFUSED')

    @patch('check_dns_auth.queries.query')
    def test_upward_referral_is_lame(self, mock_query) -> None:
        """A referral to a parent zone classifies as LAME."""
        mock_query.return_value = make_response(
            aa=False, authority=ns_rrset('com.'))
        result = self.check()
        self.assertIs(result.status, ServerStatus.LAME)
        self.assertEqual(result.detail, 'upward referral')

    @patch('check_dns_auth.queries.query')
    def test_aa_clear_is_non_authoritative(self, mock_query) -> None:
        """An answer without AA set classifies as NON_AUTHORITATIVE."""
        mock_query.return_value = make_response(aa=False, answer=soa_rrset(42))
        result = self.check()
        self.assertIs(result.status, ServerStatus.NON_AUTHORITATIVE)
        self.assertEqual(result.serial, 42)

    @patch('check_dns_auth.queries.query')
    def test_healthy_with_ns_in_authority(self, mock_query) -> None:
        """An authoritative answer with NS in AUTHORITY needs no NS query."""
        mock_query.return_value = make_response(answer=soa_rrset(100),
                                                authority=ns_rrset())
        result = self.check()
        self.assertIs(result.status, ServerStatus.HEALTHY)
        self.assertEqual(result.serial, 100)
        self.assertEqual(result.ns_names,
                         frozenset({dns.name.from_text('ns1.example.com.'),
                                    dns.name.from_text('ns2.example.com.')}))
        self.assertEqual(mock_query.call_count, 1)

    @patch('check_dns_auth.queries.query')
    def test_healthy_with_separate_ns_query(self, mock_query) -> None:
        """Without NS in the SOA response, the NS set is queried directly."""
        mock_query.side_effect = [
            make_response(answer=soa_rrset(100)),
            make_response(rr_type=dns.rdatatype.NS, answer=ns_rrset()),
        ]
        result = self.check()
        self.assertIs(result.status, ServerStatus.HEALTHY)
        self.assertEqual(len(result.ns_names), 2)
        self.assertEqual(mock_query.call_count, 2)

    @patch('check_dns_auth.queries.query')
    def test_cds_detection(self, mock_query) -> None:
        """CDS/CDNSKEY presence is recorded when requested."""
        cds = dns.rrset.from_text('example.com.', 300, 'IN', 'CDS',
                                  '12345 13 2 ' + '00' * 32)
        mock_query.side_effect = [
            make_response(answer=soa_rrset(100), authority=ns_rrset()),
            make_response(rr_type=dns.rdatatype.CDS, answer=cds),
            make_response(rr_type=dns.rdatatype.CDNSKEY),
        ]
        result = self.check(check_cds=True)
        self.assertTrue(result.cds)
        self.assertFalse(result.cdnskey)


class TestCheckServer(unittest.TestCase):
    """Tests for the check_server function."""

    @patch('check_dns_auth.queries.resolve_addresses')
    def test_unresolvable_hostname(self, mock_resolve) -> None:
        """A hostname with no addresses yields a single UNRESPONSIVE result."""
        mock_resolve.return_value = []
        results = check_server(ZONE, NS1, 5.0, False)
        self.assertEqual(len(results), 1)
        self.assertIs(results[0].status, ServerStatus.UNRESPONSIVE)
        self.assertEqual(results[0].detail, 'hostname did not resolve')
        self.assertIsNone(results[0].address)

    @patch('check_dns_auth.queries.check_address')
    @patch('check_dns_auth.queries.resolve_addresses')
    def test_one_result_per_address(self, mock_resolve, mock_check) -> None:
        """Every address of a server is checked individually."""
        mock_resolve.return_value = ['2001:db8::1', '192.0.2.1']
        check_server(ZONE, NS1, 5.0, False)
        self.assertEqual(mock_check.call_count, 2)


class TestGetDelegationNSSet(unittest.TestCase):
    """Tests for the get_delegation_ns_set function."""

    @patch('check_dns_auth.queries.query')
    @patch('check_dns_auth.queries.resolve_addresses')
    @patch('dns.resolver.Resolver.resolve')
    @patch('dns.resolver.zone_for_name')
    def test_referral_from_parent(self, mock_zone_for_name, mock_resolve,
                                  mock_addresses, mock_query) -> None:
        """An NS set in the AUTHORITY section of a referral is accepted."""
        mock_zone_for_name.return_value = dns.name.from_text('com.')
        mock_resolve.return_value = [
            Mock(target=dns.name.from_text('a.gtld-servers.net.'))]
        mock_addresses.return_value = ['192.0.2.53']
        mock_query.return_value = make_response(
            rr_type=dns.rdatatype.NS, aa=False, authority=ns_rrset())
        self.assertEqual(get_delegation_ns_set(ZONE, 5.0),
                         {dns.name.from_text('ns1.example.com.'),
                          dns.name.from_text('ns2.example.com.')})

    @patch('check_dns_auth.queries.query')
    @patch('check_dns_auth.queries.resolve_addresses')
    @patch('dns.resolver.Resolver.resolve')
    @patch('dns.resolver.zone_for_name')
    def test_no_answer_raises_checkerror(self, mock_zone_for_name, mock_resolve,
                                         mock_addresses, mock_query) -> None:
        """Unresponsive parent servers raise CheckError (UNKNOWN)."""
        mock_zone_for_name.return_value = dns.name.from_text('com.')
        mock_resolve.return_value = [
            Mock(target=dns.name.from_text('a.gtld-servers.net.'))]
        mock_addresses.return_value = ['192.0.2.53']
        mock_query.return_value = None
        with self.assertRaises(nagiosplugin.CheckError):
            get_delegation_ns_set(ZONE, 5.0)

    @patch('check_dns_auth.queries.query')
    @patch('check_dns_auth.queries.resolve_addresses')
    @patch('dns.resolver.Resolver.resolve')
    @patch('dns.resolver.zone_for_name')
    def test_no_delegation_names_the_rcode(self, mock_zone_for_name,
                                           mock_resolve, mock_addresses,
                                           mock_query) -> None:
        """A parent that answers without a delegation reports the rcode."""
        mock_zone_for_name.return_value = dns.name.from_text('com.')
        mock_resolve.return_value = [
            Mock(target=dns.name.from_text('a.gtld-servers.net.'))]
        mock_addresses.return_value = ['192.0.2.53']
        mock_query.return_value = make_response(
            rr_type=dns.rdatatype.NS, rcode=dns.rcode.NXDOMAIN, aa=False)
        with self.assertRaisesRegex(nagiosplugin.CheckError, 'NXDOMAIN'):
            get_delegation_ns_set(ZONE, 5.0)

    @patch('dns.resolver.zone_for_name')
    def test_parent_lookup_failure_raises_checkerror(self,
                                                     mock_zone_for_name) -> None:
        """Failure to find the parent zone raises CheckError (UNKNOWN)."""
        mock_zone_for_name.side_effect = dns.resolver.NoRootSOA()
        with self.assertRaises(nagiosplugin.CheckError):
            get_delegation_ns_set(ZONE, 5.0)
