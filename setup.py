"""
Check DNS Auth

An Icinga/Nagios plugin that checks that all authoritative nameservers for a
zone have the same NS RRset and the same serial number.  It can also
optionally accept an NS RRset on the commandline to enforce, and/or alert on
the presence of CDS/CDNSKEY records.
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

from setuptools import setup, find_packages

import check_dns_auth

setup(
    name="check-dns-auth",
    version=check_dns_auth.__version__,
    description=("Nagios/Icinga plugin to check "
                 "NS RRsets and serial numbers for a zone."),
    long_description=__doc__,
    keywords="application Icinga monitoring",
    url="https://github.com/Nimbus-Operations/check-dns-auth",
    download_url="https://pypi.org/project/check-dns-auth/",
    project_urls={
        'check-dns-auth source':
            'https://github.com/Nimbus-Operations/check-dns-auth',
        'check-dns-auth issues':
            'https://github.com/Nimbus-Operations/check-dns-auth/issues',
    },
    author="Matthew Pounsett",
    author_email="matt@NimbusOps.com",
    license="Apache",

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
    ],

    packages=find_packages(),
    scripts=['check_dns_auth.py'],
    install_requires=[
        'nagiosplugin >=1.3, <2.0',
    ],
    python_requires='>=3.9',

    entry_points={
        'console_scripts': [
            'check_dns_auth = check_dns_auth:main',
        ]
    },
)
