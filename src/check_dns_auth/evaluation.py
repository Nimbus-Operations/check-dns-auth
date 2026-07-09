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
"""Evaluation of collected server data into metrics and findings."""

import dns.name

from check_dns_auth.model import ServerResult, ServerStatus

SERIAL_MODULUS = 2 ** 32


def serial_distance(a: int, b: int) -> int:
    """Distance between two serial numbers under RFC 1982 serial arithmetic."""
    forward = (a - b) % SERIAL_MODULUS
    return min(forward, SERIAL_MODULUS - forward)


def _format_ns_set(ns_names) -> str:
    return '{' + ', '.join(sorted(name.to_text() for name in ns_names)) + '}'


def evaluate(results: list[ServerResult],  # pylint: disable=too-many-locals
             reference_ns: set[dns.name.Name]) -> tuple[dict, dict]:
    """Reduce per-server results to metric values and human-readable findings.

    Only healthy (responding, authoritative) server instances participate in
    the NS-set, serial, and CDS comparisons; the rest are reported through
    their own metrics.

    Args:
        results: one ServerResult per (server, address) instance checked.
        reference_ns: the required NS set (delegation set plus any --ns names).

    Returns:
        (metrics, findings): both keyed by metric name.  metrics values are
        ints; finding values are detail strings present only for metrics
        with something to report.
    """
    metrics: dict[str, int] = {}
    findings: dict[str, str] = {}

    def labels(subset, with_detail=False):
        return ', '.join(
            f"{r.label()} [{r.detail}]" if with_detail and r.detail else r.label()
            for r in subset)

    for status, metric, message in (
            (ServerStatus.UNRESPONSIVE, 'unresponsive', 'no response from'),
            (ServerStatus.LAME, 'lame', 'lame server(s):'),
            (ServerStatus.NON_AUTHORITATIVE, 'non_authoritative',
             'non-authoritative answers from')):
        subset = [r for r in results if r.status is status]
        metrics[metric] = len(subset)
        if subset:
            findings[metric] = f"{message} {labels(subset, with_detail=True)}"

    healthy = [r for r in results if r.status is ServerStatus.HEALTHY]

    # Parent (or required) NS set vs. the union of all apex NS sets.  Skipped
    # when no healthy server produced an NS set: there is nothing meaningful
    # to compare, and the unresponsive/lame findings already tell the story.
    apex_union: set = set().union(
        *(r.ns_names for r in healthy if r.ns_names is not None))
    metrics['parent_ns_mismatch'] = 0
    if apex_union and reference_ns:
        missing = reference_ns - apex_union
        extra = apex_union - reference_ns
        if missing or extra:
            metrics['parent_ns_mismatch'] = 1
            parts = []
            if missing:
                parts.append(f"missing from apex: {_format_ns_set(missing)}")
            if extra:
                parts.append(f"not in delegation: {_format_ns_set(extra)}")
            findings['parent_ns_mismatch'] = (
                'apex/delegation NS mismatch: ' + '; '.join(parts))

    # Apex NS agreement between servers: bucket servers by their NS set and
    # report the buckets, rather than trying to elect a "correct" set.
    buckets: dict[frozenset, list[ServerResult]] = {}
    for result in healthy:
        if result.ns_names is not None:
            buckets.setdefault(result.ns_names, []).append(result)
    metrics['ns_disagreement'] = max(len(buckets) - 1, 0)
    if len(buckets) > 1:
        findings['ns_disagreement'] = 'apex NS sets disagree: ' + '; '.join(
            f"[{labels(members)}] have {_format_ns_set(ns_names)}"
            for ns_names, members in buckets.items())

    serials = {r.serial for r in healthy if r.serial is not None}
    metrics['serial_spread'] = max(
        (serial_distance(a, b) for a in serials for b in serials), default=0)
    if len(serials) > 1:
        by_serial: dict[int, list[ServerResult]] = {}
        for result in healthy:
            if result.serial is not None:
                by_serial.setdefault(result.serial, []).append(result)
        findings['serial_spread'] = (
            f"serials disagree (spread {metrics['serial_spread']}): " + '; '.join(
                f"{serial} [{labels(members)}]"
                for serial, members in sorted(by_serial.items(), reverse=True)))

    flagged = [r for r in healthy if r.cds or r.cdnskey]
    metrics['cds_present'] = len(flagged)
    if flagged:
        findings['cds_present'] = 'CDS/CDNSKEY records present on ' + ', '.join(
            f"{r.label()} "
            f"[{'/'.join(t for t, p in (('CDS', r.cds), ('CDNSKEY', r.cdnskey)) if p)}]"
            for r in flagged)

    return metrics, findings
