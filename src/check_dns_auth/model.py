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
"""Data types describing the state of a zone's name servers."""

import enum
from dataclasses import dataclass
from typing import Optional

import dns.name


class ServerStatus(enum.Enum):
    """Classification of a single name server instance's response."""

    # Answered the SOA query for the zone with AA set.
    HEALTHY = 'healthy'
    # No response at all (timeout, network error, or unresolvable hostname).
    UNRESPONSIVE = 'unresponsive'
    # Responded, but without an answer for the zone: REFUSED, SERVFAIL,
    # an upward referral, or some other non-answer.
    LAME = 'lame'
    # Returned an answer for the zone, but with AA clear: answering from
    # cache, forwarding, or some other non-authoritative mechanism.
    NON_AUTHORITATIVE = 'non-authoritative'


@dataclass
class ServerResult:
    """Results of querying a single (name server, address) instance."""

    # pylint: disable=too-many-instance-attributes
    name: dns.name.Name
    address: Optional[str]
    status: ServerStatus
    detail: str = ''
    serial: Optional[int] = None
    # The apex NS set as reported by this instance; None means it could not
    # be obtained.  When set, it is non-empty: a DNS response cannot carry an
    # empty rrset, and evaluation relies on None being the only "no data" value.
    ns_names: Optional[frozenset[dns.name.Name]] = None
    cds: bool = False
    cdnskey: bool = False

    def label(self) -> str:
        """Human-readable identifier for this server instance."""
        return f"{self.name.to_text()} ({self.address or 'unresolved'})"
