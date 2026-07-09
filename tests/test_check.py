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
"""Tests for the Zone resource and ZoneSummary."""
import unittest
from unittest.mock import patch

import dns.name
import nagiosplugin

from check_dns_auth.check import Zone, ZoneSummary
from check_dns_auth.cli import parse_args
from check_dns_auth.model import ServerResult, ServerStatus


def name(text: str) -> dns.name.Name:
    """Shorthand for dns.name.from_text."""
    return dns.name.from_text(text)


NS1 = name('ns1.example.com.')
NS2 = name('ns2.example.com.')
NS_SET = frozenset({NS1, NS2})


def healthy(host: dns.name.Name, address='192.0.2.1', serial=100,
            ns=NS_SET) -> ServerResult:
    """Build a HEALTHY ServerResult with sensible defaults."""
    return ServerResult(host, address, ServerStatus.HEALTHY,
                        serial=serial, ns_names=ns)


class TestZoneProbe(unittest.TestCase):
    """Tests for the Zone.probe data collection and metric generation."""

    @patch('check_dns_auth.check.check_server')
    @patch('check_dns_auth.check.get_delegation_ns_set')
    def test_discovery_of_apex_only_servers(self, mock_delegation,
                                            mock_check_server) -> None:
        """Servers only present in apex NS sets are discovered and checked."""
        # The delegation only knows ns1, but ns1's apex NS set names ns2.
        mock_delegation.return_value = {NS1}
        responses = {
            NS1: [healthy(NS1, '192.0.2.1')],
            NS2: [healthy(NS2, '192.0.2.2')],
        }
        mock_check_server.side_effect = (
            lambda zone, server, timeout, cds, families: responses[server])

        zone = Zone(parse_args(['-z', 'example.com']))
        metrics = {metric.name: metric.value for metric in zone.probe()}

        self.assertEqual(mock_check_server.call_count, 2)
        self.assertEqual(zone.instance_count, 2)
        self.assertEqual(zone.serial, 100)
        self.assertEqual(metrics, {
            'unresponsive': 0,
            'lame': 0,
            'non_authoritative': 0,
            # ns2 is in the apex sets but not the delegation.
            'parent_ns_mismatch': 1,
            'ns_disagreement': 0,
            'serial_spread': 0,
        })

    @patch('check_dns_auth.check.check_server')
    @patch('check_dns_auth.check.get_delegation_ns_set')
    def test_skipped_checks_yield_no_metrics(self, mock_delegation,
                                             mock_check_server) -> None:
        """-N and -S suppress their metrics; --cds adds one."""
        mock_delegation.return_value = {NS1}
        mock_check_server.return_value = [healthy(NS1)]

        zone = Zone(parse_args(['-z', 'example.com', '-N', '-S',
                                '-c', 'warning']))
        metrics = {metric.name for metric in zone.probe()}
        self.assertEqual(metrics, {'unresponsive', 'lame',
                                   'non_authoritative', 'cds_present'})

    @patch('check_dns_auth.check.check_server')
    def test_no_parent_skips_delegation_lookup(self,
                                               mock_check_server) -> None:
        """--no-parent seeds the check from the --ns list alone."""
        mock_check_server.return_value = [healthy(NS1, ns=frozenset({NS1}))]
        zone = Zone(parse_args(['-z', 'example.com', '--no-parent',
                                '-n', 'ns1.example.com']))
        metrics = {metric.name: metric.value for metric in zone.probe()}
        self.assertEqual(metrics['parent_ns_mismatch'], 0)


class TestZoneSummary(unittest.TestCase):
    """Tests for the ZoneSummary output rendering."""

    def make_zone(self, findings) -> Zone:
        """Build a Zone with canned summary data, as if probe() had run."""
        zone = Zone(parse_args(['-z', 'example.com']))
        zone.findings = findings
        zone.instance_count = 2
        zone.serial = 100
        return zone

    def test_ok(self) -> None:
        """The OK message includes the zone, instance count, and serial."""
        summary = ZoneSummary(self.make_zone({}))
        self.assertEqual(summary.ok(nagiosplugin.Results()),
                         'example.com. is consistent across 2 server '
                         'instances (serial 100)')

    def test_problem_renders_findings(self) -> None:
        """Non-OK results are rendered from the recorded findings."""
        summary = ZoneSummary(self.make_zone(
            {'lame': 'lame server(s): ns1.example.com. (192.0.2.1)'}))
        results = nagiosplugin.Results()
        results.add(nagiosplugin.Result(
            nagiosplugin.Critical, metric=nagiosplugin.Metric('lame', 1)))
        self.assertEqual(summary.problem(results),
                         'lame server(s): ns1.example.com. (192.0.2.1)')

    def test_problem_without_metric_falls_back(self) -> None:
        """A metric-less result (e.g. from CheckError) uses the default text."""
        summary = ZoneSummary(self.make_zone({}))
        results = nagiosplugin.Results()
        results.add(nagiosplugin.Result(nagiosplugin.Unknown, 'boom'))
        self.assertIn('boom', summary.problem(results))
