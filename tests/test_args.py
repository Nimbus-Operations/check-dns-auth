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
"""Tests for command line parsing and threshold derivation."""
import unittest

from check_dns_auth.cli import parse_args, serial_thresholds


class TestParseArgs(unittest.TestCase):
    """Tests for the parse_args function."""

    def test_minimal(self) -> None:
        """Only --zone is required; check the defaults."""
        args = parse_args(['-z', 'example.com'])
        self.assertEqual(args.zone, 'example.com')
        self.assertEqual(args.ns, [])
        self.assertFalse(args.no_parent)
        self.assertIsNone(args.serial_warning)
        self.assertIsNone(args.serial_critical)
        self.assertIsNone(args.cds)
        self.assertEqual(args.timeout, 5.0)

    def test_zone_required(self) -> None:
        """Omitting --zone is an error."""
        with self.assertRaises(SystemExit):
            parse_args([])

    def test_ns_accumulates(self) -> None:
        """--ns may be given multiple times."""
        args = parse_args(['-z', 'example.com',
                           '-n', 'ns1.example.net', '-n', 'ns2.example.net'])
        self.assertEqual(args.ns, ['ns1.example.net', 'ns2.example.net'])

    def test_no_parent_requires_ns(self) -> None:
        """--no-parent without any --ns is an error."""
        with self.assertRaises(SystemExit):
            parse_args(['-z', 'example.com', '--no-parent'])

    def test_no_parent_with_ns(self) -> None:
        """--no-parent with an --ns is accepted."""
        args = parse_args(['-z', 'example.com', '--no-parent',
                           '-n', 'ns1.example.net'])
        self.assertTrue(args.no_parent)

    def test_address_families(self) -> None:
        """-4 and -6 are accepted, separately or together."""
        args = parse_args(['-z', 'example.com', '-4'])
        self.assertTrue(args.ipv4)
        self.assertFalse(args.ipv6)
        args = parse_args(['-z', 'example.com', '-4', '-6'])
        self.assertTrue(args.ipv4)
        self.assertTrue(args.ipv6)


class TestSerialThresholds(unittest.TestCase):
    """Tests for the serial threshold derivation rule."""

    def test_default_any_spread_is_critical(self) -> None:
        """With neither threshold set, any spread is CRITICAL."""
        args = parse_args(['-z', 'example.com'])
        self.assertEqual(serial_thresholds(args), ('', '0'))

    def test_warning_only(self) -> None:
        """Only --serial-warning: warning above N, no critical."""
        args = parse_args(['-z', 'example.com', '--serial-warning', '10'])
        self.assertEqual(serial_thresholds(args), ('10', ''))

    def test_critical_only(self) -> None:
        """Only --serial-critical: critical above N, no warning."""
        args = parse_args(['-z', 'example.com', '--serial-critical', '100'])
        self.assertEqual(serial_thresholds(args), ('', '100'))

    def test_both(self) -> None:
        """Both thresholds give the usual two-tier behaviour."""
        args = parse_args(['-z', 'example.com',
                           '--serial-warning', '10',
                           '--serial-critical', '100'])
        self.assertEqual(serial_thresholds(args), ('10', '100'))
