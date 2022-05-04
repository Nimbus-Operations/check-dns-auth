"""
An Icinga/Nagios-compatible plugin that checks authoritative name servers
for a zone to ensure they have synchronized NS RRsets and serial numbers.
It can optionally require a particular NS RRset and/or alert on the presence of
CDS/CDNSKEY records.
"""
# ==============================================================================
#  Copyright © 2022 Matthew Pounsett <matt@NimbusOps.com>
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

__version__ = "0.0.1"
_LOG = logging.getLogger('nagiosplugin')

