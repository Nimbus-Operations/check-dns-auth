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
"""The nagiosplugin Resource and Summary implementing the zone check."""

import argparse
from typing import Optional

import dns.name
import dns.rdatatype
import nagiosplugin

from check_dns_auth.evaluation import evaluate
from check_dns_auth.model import ServerResult, ServerStatus
from check_dns_auth.queries import (ALL_FAMILIES, Families, check_server,
                                    get_delegation_ns_set)


class Zone(nagiosplugin.Resource):
    """nagiosplugin.Resource representation of a DNS zone."""

    def __init__(self, args: argparse.Namespace):
        """Initialize the resource from parsed command line arguments."""
        self.args = args
        self.zone = dns.name.from_text(args.zone)
        self.extra_ns = {dns.name.from_text(ns) for ns in args.ns}
        # Findings and summary data populated by probe(), read by ZoneSummary.
        self.findings: dict[str, str] = {}
        self.instance_count = 0
        self.serial: Optional[int] = None

    def probe(self):
        """Collect data from all of the zone's name servers and emit metrics."""
        args = self.args
        families: Families
        if args.ipv6 and not args.ipv4:
            families = (dns.rdatatype.AAAA,)
        elif args.ipv4 and not args.ipv6:
            families = (dns.rdatatype.A,)
        else:
            families = ALL_FAMILIES
        reference_ns = set(self.extra_ns)
        if not args.no_parent:
            reference_ns |= get_delegation_ns_set(self.zone, args.timeout,
                                                  families)

        # Query every server in the reference NS set, plus any additional
        # server names discovered in the apex NS sets they return.
        results: list[ServerResult] = []
        pending = set(reference_ns)
        seen: set[dns.name.Name] = set()
        while pending:
            name = pending.pop()
            seen.add(name)
            for result in check_server(self.zone, name, args.timeout,
                                       bool(args.cds), families):
                results.append(result)
                if result.ns_names:
                    pending |= set(result.ns_names) - seen

        metrics, self.findings = evaluate(results, reference_ns)
        self.instance_count = len(results)
        serials = {r.serial for r in results if r.status is ServerStatus.HEALTHY}
        self.serial = serials.pop() if len(serials) == 1 else None

        for metric in ('unresponsive', 'lame', 'non_authoritative'):
            yield nagiosplugin.Metric(metric, metrics[metric], min=0)
        if not args.no_ns_check:
            yield nagiosplugin.Metric('parent_ns_mismatch',
                                      metrics['parent_ns_mismatch'], min=0)
            yield nagiosplugin.Metric('ns_disagreement',
                                      metrics['ns_disagreement'], min=0)
        if not args.no_serial_check:
            yield nagiosplugin.Metric('serial_spread',
                                      metrics['serial_spread'], min=0)
        if args.cds:
            yield nagiosplugin.Metric('cds_present', metrics['cds_present'], min=0)


class ZoneSummary(nagiosplugin.Summary):
    """Render detailed findings recorded by the Zone resource during probe()."""

    def __init__(self, zone: Zone):
        """Attach the Zone resource whose findings will be rendered."""
        self.zone = zone

    def ok(self, results) -> str:
        """Summarize a healthy zone in one line."""
        message = (f"{self.zone.zone} is consistent across "
                   f"{self.zone.instance_count} server instances")
        if self.zone.serial is not None:
            message += f" (serial {self.zone.serial})"
        return message

    def problem(self, results) -> str:
        """Render the findings behind every non-OK result."""
        # A CheckError raised in probe() produces a result with no metric;
        # fall through to the default summary (the error message) for those.
        texts = [self.zone.findings[result.metric.name] for result in results
                 if result.state != nagiosplugin.Ok and result.metric is not None
                 and result.metric.name in self.zone.findings]
        return '; '.join(texts) or super().problem(results)

    def verbose(self, results) -> list[str]:
        """Return every finding as additional detail lines."""
        return list(self.zone.findings.values())
