# mitreattack-python

[![PyPI version](https://img.shields.io/pypi/v/mitreattack-python.svg)](https://pypi.org/project/mitreattack-python/) [![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/) [![License](https://img.shields.io/pypi/l/mitreattack-python.svg)](https://github.com/mitre-attack/mitreattack-python/blob/main/LICENSE) [![Docs](https://img.shields.io/readthedocs/mitreattack-python.svg)](https://mitreattack-python.readthedocs.io/) [![Lint and Test](https://img.shields.io/github/actions/workflow/status/mitre-attack/mitreattack-python/lint-and-test.yml?label=lint%20%26%20test)](https://github.com/mitre-attack/mitreattack-python/actions/workflows/lint-and-test.yml) [![Release and Publish](https://img.shields.io/github/actions/workflow/status/mitre-attack/mitreattack-python/release-and-publish.yml?branch=main&label=release)](https://github.com/mitre-attack/mitreattack-python/actions/workflows/release-and-publish.yml)

This repository contains a library of Python tools and utilities for working with ATT&CK data.
For more information, see the [full documentation](https://mitreattack-python.readthedocs.io/) on ReadTheDocs.

## Install

To use this package, install the mitreattack-python library with [pip](https://pip.pypa.io/en/stable/):

```shell
pip install mitreattack-python
```

## MitreAttackData Library

The ``MitreAttackData`` library is used to read in and work with MITRE ATT&CK STIX 2.0 content. This library provides
the ability to query the dataset for objects and their related objects. This is the main content of mitreattack-python;
you can read more about other modules in this library under "Additional Modules".

## Related MITRE Work

### CTI

[Cyber Threat Intelligence repository](https://github.com/mitre/cti) of the ATT&CK catalog expressed in STIX 2.0 JSON.
This repository also contains [our USAGE document](https://github.com/mitre/cti/blob/master/USAGE.md) which includes
additional examples of accessing and parsing our dataset in Python.

### ATT&CK

ATT&CK® is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of
an adversary’s lifecycle, and the platforms they are known to target.
ATT&CK is useful for understanding security risk against known adversary behavior,
for planning security improvements, and verifying defenses work as expected.

<https://attack.mitre.org>

### STIX

Structured Threat Information Expression (STIX<sup>™</sup>) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine-readable manner,
allowing security communities to better understand what computer-based attacks they are most likely to
see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

<https://oasis-open.github.io/cti-documentation/>

## Contributing

To contribute to this project, either through a bug report, feature request, or merge request,
please see the [Contributors Guide](https://github.com/mitre-attack/mitreattack-python/blob/main/docs/CONTRIBUTING.md).
