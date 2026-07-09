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
"""Icinga/Nagios-compatible plugin checking a zone's authoritative servers.

Checks authoritative name servers for a zone to ensure they have
synchronized NS RR sets and serial numbers.  It can optionally require a
particular NS RR set and/or alert on the presence of CDS/CDNSKEY records.
"""

from check_dns_auth.version import __version__

__all__ = ["__version__"]
