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
"""Command line interface for the check_dns_auth plugin."""

import argparse
import inspect
import sys

import nagiosplugin

from check_dns_auth.check import Zone, ZoneSummary


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

            Optionally require additional NS names beyond the delegation set,
            and/or alert on the presence of CDS/CDNSKEY records.
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
        default=[],
        help=(
            "Add a name server to the required NS RR set, in addition to the "
            "delegation NS set from the parent.  May be specified multiple times."
        ),
    )
    parser.add_argument(
        '--no-parent',
        action='store_true',
        help=(
            "Skip obtaining the delegation NS set from the parent zone; the "
            "required NS set is then only the --ns list (requires at least "
            "one --ns)."
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
        '--serial-warning',
        metavar='SPREAD',
        type=int,
        help=(
            "Return WARNING if the SOA serial spread across servers exceeds "
            "SPREAD.  If neither serial threshold is given, any spread is "
            "CRITICAL."
        ),
    )
    parser.add_argument(
        '--serial-critical',
        metavar='SPREAD',
        type=int,
        help=(
            "Return CRITICAL if the SOA serial spread across servers exceeds "
            "SPREAD.  If neither serial threshold is given, any spread is "
            "CRITICAL."
        ),
    )
    parser.add_argument(
        '-c', '--cds',
        choices=['warning', 'critical'],
        default=None,
        help="If CDS or CDNSKEY records are present in the zone, return the requested status.",
    )
    parser.add_argument(
        '-4', '--ipv4',
        action='store_true',
        help="Only check IPv4 addresses.  May be combined with -6.",
    )
    parser.add_argument(
        '-6', '--ipv6',
        action='store_true',
        help="Only check IPv6 addresses.  May be combined with -4.",
    )
    parser.add_argument(
        '-t', '--timeout',
        metavar='SECONDS',
        type=float,
        default=5.0,
        help="Timeout for each individual DNS query.  Defaults to 5 seconds.",
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help="Increase output verbosity (use up to 3 times).",
    )
    parsed = parser.parse_args(args)
    if parsed.no_parent and not parsed.ns:
        parser.error('--no-parent requires at least one --ns')
    return parsed


def serial_thresholds(args: argparse.Namespace) -> tuple[str, str]:
    """Derive (warning, critical) ranges for serial spread from the arguments.

    A threshold that is explicitly set is the behaviour you get; with neither
    set, any spread at all is CRITICAL.
    """
    if args.serial_warning is None and args.serial_critical is None:
        return '', '0'
    return (str(args.serial_warning) if args.serial_warning is not None else '',
            str(args.serial_critical) if args.serial_critical is not None else '')


def setup_check(args: argparse.Namespace) -> None:
    """Set up and run the actual check."""
    serial_warning, serial_critical = serial_thresholds(args)
    contexts = [
        nagiosplugin.ScalarContext('unresponsive', '', '0'),
        nagiosplugin.ScalarContext('lame', '', '0'),
        nagiosplugin.ScalarContext('non_authoritative', '', '0'),
        nagiosplugin.ScalarContext('parent_ns_mismatch', '0', ''),
        nagiosplugin.ScalarContext('ns_disagreement', '', '0'),
        nagiosplugin.ScalarContext('serial_spread', serial_warning, serial_critical),
        nagiosplugin.ScalarContext('cds_present',
                                   '0' if args.cds == 'warning' else '',
                                   '0' if args.cds == 'critical' else ''),
    ]
    zone = Zone(args)
    check = nagiosplugin.Check(zone, *contexts, ZoneSummary(zone))
    check.main(verbose=args.verbose)


@nagiosplugin.guarded(verbose=0)
def main() -> None:
    """Run the check-dns-auth script.  This is the main entrypoint."""
    args = parse_args()
    setup_check(args)


if __name__ == '__main__':
    main()
