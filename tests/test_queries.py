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
import logging
import unittest

from unittest.mock import patch, Mock, call

import dns.name

from check_dns_auth import get_addresses


class CheckQueryFunctions(unittest.TestCase):
    """Basic tests for DNS query functions."""

    def setUp(self) -> None:
        """Set up the class for testing."""
        self.log = logging.getLogger(__name__)

    @patch('dns.resolver.Resolver.resolve')
    def test_get_addresses(self, mock_resolve) -> None:
        """Test the get_addresses function."""
        fake_v6 = [Mock(address='2001:db8::1')]
        fake_answer_v6 = Mock()
        fake_answer_v6.response = Mock()
        fake_answer_v6.response.get_rrset = Mock(return_value=fake_v6)
        fake_v4 = [Mock(address='192.0.2.1')]
        fake_answer_v4 = Mock()
        fake_answer_v4.response = Mock()
        fake_answer_v4.response.get_rrset = Mock(return_value=fake_v4)

        mock_resolve.side_effect = [fake_answer_v6, fake_answer_v4]

        hostname = 'ns1.example.com.'
        results = get_addresses(dns.name.from_text(hostname))
        self.log.debug("test_get_addresses results: %s", results)

        self.assertEqual(results, ['2001:db8::1', '192.0.2.1'])
        expected_calls = [
            call(hostname, dns.rdatatype.AAAA),
            call(hostname, dns.rdatatype.A),
        ]
        mock_resolve.assert_has_calls(expected_calls, any_order=False)
        self.assertEqual(mock_resolve.call_count, 2)


    @patch('dns.query.udp_with_fallback')
    def test_update_server_data(self, mock_query_fallback) -> None:
        """Test the update_server_data function."""




