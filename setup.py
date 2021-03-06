#!/usr/bin/env python
"""Assemblyline Client Incident Response Manager Library PiP Installer"""

import os
from setuptools import setup, find_packages

# For development and local builds use this version number, but for real builds replace it
# with the tag found in the environment
package_version = "4.0.0.dev0"
if 'BITBUCKET_TAG' in os.environ:
    package_version = os.environ['BITBUCKET_TAG'].lstrip('v')
elif 'BUILD_SOURCEBRANCH' in os.environ:
    full_tag_prefix = 'refs/tags/v'
    package_version = os.environ['BUILD_SOURCEBRANCH'][len(full_tag_prefix):]

# read the contents of the README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as f:
    long_description = f.read()

setup(
    name='assemblyline-incident-manager',
    version=package_version,
    description='Assemblyline v4 client incident manager library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    url='https://github.com/CybercentreCanada/assemblyline-incident-manager',
    author='CSE-CST Assemblyline development team',
    author_email='assemblyline@cyber.gc.ca',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    entry_points={
        'console_scripts': [
            'al-incident-submitter=assemblyline_incident_manager.al_incident_submitter:main',
            'al-incident-analyzer=assemblyline_incident_manager.al_incident_analyzer:main',
            'al-incident-downloader=assemblyline_incident_manager.al_incident_downloader:main',
        ],
    },
    install_requires=[
        'assemblyline-client',
        'click',
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest_mock'
        ]
    },
    keywords='development assemblyline client incident gc canada cse-cst cse cst',
    packages=find_packages(exclude=['test/*'])
)