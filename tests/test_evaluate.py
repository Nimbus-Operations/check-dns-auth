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
"""Tests for the pure evaluation logic."""
import unittest

import dns.name

from check_dns_auth.evaluation import evaluate, serial_distance
from check_dns_auth.model import ServerResult, ServerStatus


def name(text: str) -> dns.name.Name:
    """Shorthand for dns.name.from_text."""
    return dns.name.from_text(text)


NS_SET = frozenset({name('ns1.example.com.'), name('ns2.example.com.')})


def healthy(host: str, address='192.0.2.1', serial=100, ns=NS_SET,
            **kwargs) -> ServerResult:
    """Build a HEALTHY ServerResult with sensible defaults."""
    return ServerResult(name(host), address, ServerStatus.HEALTHY,
                        serial=serial, ns_names=ns, **kwargs)


class TestSerialDistance(unittest.TestCase):
    """Tests for RFC 1982 serial distance."""

    def test_simple(self) -> None:
        """Ordinary distances are plain differences."""
        self.assertEqual(serial_distance(100, 90), 10)
        self.assertEqual(serial_distance(90, 100), 10)
        self.assertEqual(serial_distance(100, 100), 0)

    def test_wraparound(self) -> None:
        """Distance across the 2^32 boundary is measured the short way."""
        self.assertEqual(serial_distance(4294967290, 5), 11)
        self.assertEqual(serial_distance(5, 4294967290), 11)


class TestEvaluate(unittest.TestCase):
    """Tests for the evaluate function."""

    def test_all_consistent(self) -> None:
        """A fully consistent zone produces zero metrics and no findings."""
        results = [healthy('ns1.example.com.'),
                   healthy('ns2.example.com.', address='192.0.2.2')]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics, {
            'unresponsive': 0,
            'lame': 0,
            'non_authoritative': 0,
            'parent_ns_mismatch': 0,
            'ns_disagreement': 0,
            'serial_spread': 0,
            'cds_present': 0,
        })
        self.assertEqual(findings, {})

    def test_unresponsive_and_lame_reported(self) -> None:
        """Broken servers are counted and named, with detail."""
        results = [
            healthy('ns1.example.com.'),
            ServerResult(name('ns2.example.com.'), '192.0.2.2',
                         ServerStatus.UNRESPONSIVE, 'no response'),
            ServerResult(name('ns3.example.com.'), '192.0.2.3',
                         ServerStatus.LAME, 'REFUSED'),
        ]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['unresponsive'], 1)
        self.assertEqual(metrics['lame'], 1)
        self.assertIn('ns2.example.com. (192.0.2.2) [no response]',
                      findings['unresponsive'])
        self.assertIn('ns3.example.com. (192.0.2.3) [REFUSED]',
                      findings['lame'])

    def test_non_authoritative_excluded_from_comparisons(self) -> None:
        """A non-authoritative server's serial does not affect the spread."""
        results = [
            healthy('ns1.example.com.', serial=100),
            healthy('ns2.example.com.', address='192.0.2.2', serial=100),
            ServerResult(name('ns3.example.com.'), '192.0.2.3',
                         ServerStatus.NON_AUTHORITATIVE, serial=50),
        ]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['non_authoritative'], 1)
        self.assertEqual(metrics['serial_spread'], 0)
        self.assertIn('ns3.example.com. (192.0.2.3)',
                      findings['non_authoritative'])

    def test_ns_disagreement_buckets(self) -> None:
        """Servers are grouped by NS set and each group is reported."""
        small_set = frozenset({name('ns1.example.com.')})
        results = [
            healthy('ns1.example.com.'),
            healthy('ns2.example.com.', address='192.0.2.2', ns=small_set),
        ]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['ns_disagreement'], 1)
        self.assertIn('apex NS sets disagree', findings['ns_disagreement'])
        self.assertIn('ns1.example.com. (192.0.2.1)',
                      findings['ns_disagreement'])
        self.assertIn('{ns1.example.com.}', findings['ns_disagreement'])

    def test_parent_mismatch(self) -> None:
        """Missing and extra names vs. the reference set are both reported."""
        reference = {name('ns1.example.com.'), name('ns3.example.com.')}
        results = [healthy('ns1.example.com.')]
        metrics, findings = evaluate(results, reference)
        self.assertEqual(metrics['parent_ns_mismatch'], 1)
        self.assertIn('missing from apex: {ns3.example.com.}',
                      findings['parent_ns_mismatch'])
        self.assertIn('not in delegation: {ns2.example.com.}',
                      findings['parent_ns_mismatch'])

    def test_parent_check_skipped_without_healthy_servers(self) -> None:
        """With no healthy servers there is no apex set to compare."""
        results = [ServerResult(name('ns1.example.com.'), '192.0.2.1',
                                ServerStatus.LAME, 'SERVFAIL')]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['parent_ns_mismatch'], 0)
        self.assertNotIn('parent_ns_mismatch', findings)

    def test_serial_spread_and_grouping(self) -> None:
        """Serial disagreement reports each serial with its servers."""
        results = [
            healthy('ns1.example.com.', serial=110),
            healthy('ns2.example.com.', address='192.0.2.2', serial=110),
            healthy('ns3.example.com.', address='192.0.2.3', serial=100),
        ]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['serial_spread'], 10)
        self.assertIn('spread 10', findings['serial_spread'])
        self.assertIn(
            '110 [ns1.example.com. (192.0.2.1), ns2.example.com. (192.0.2.2)]',
            findings['serial_spread'])
        self.assertIn('100 [ns3.example.com. (192.0.2.3)]',
                      findings['serial_spread'])

    def test_serial_spread_wraparound(self) -> None:
        """Spread is computed with serial arithmetic, not plain subtraction."""
        results = [
            healthy('ns1.example.com.', serial=4294967290),
            healthy('ns2.example.com.', address='192.0.2.2', serial=5),
        ]
        metrics, _ = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['serial_spread'], 11)

    def test_cds_present(self) -> None:
        """Servers with CDS or CDNSKEY are counted and named with the type."""
        results = [
            healthy('ns1.example.com.', cds=True),
            healthy('ns2.example.com.', address='192.0.2.2',
                    cds=True, cdnskey=True),
        ]
        metrics, findings = evaluate(results, set(NS_SET))
        self.assertEqual(metrics['cds_present'], 2)
        self.assertIn('ns1.example.com. (192.0.2.1) [CDS]',
                      findings['cds_present'])
        self.assertIn('ns2.example.com. (192.0.2.2) [CDS/CDNSKEY]',
                      findings['cds_present'])
