# v5.0.0 - 1 August 2025

## Features

- Update minimum python version to be 3.11 for type hinting
- Update GitHub Actions to use Python version 3.11

# v4.0.3 - 1 August 2025

## Features

- Add type hints to MitreAttackData class

# v4.0.2 - 7 May 2025

## Fixes

- Update STIX 2.1 SHA256 sums for ATT&CK v17.1

# v4.0.1 - 6 May 2025

## Features

- Update library to work with ATT&CK v17.1

# v4.0.0 - 22 April 2025

## Breaking change

- Removed TAXII 2.0 functionality for multiple scripts due to cti-taxii.mitre.org going offline December 2024

## Fixes

- Fix detailed changelog HTML generation

# v3.0.8 - 12 November 2024

## Features

- Update library to work with ATT&CK v16.1

# v3.0.7 - 31 October 2024

## Features

- Update library to work with ATT&CK v16.0 new platform names

# v3.0.6 - 5/2/2024

## Fixes

- Update release information for ATT&CK 15.1... for real this time

# v3.0.5 - 5/2/2024

## Features

- Update release information for ATT&CK 15.1
- Added functionality to `MitreAttackData` to retrieve a list of Procedure Examples by technique. [#172](https://github.com/mitre-attack/mitreattack-python/pull/172)
- Updated `navlayers` module to support Navigator version 5.0.0.

## Fixes

- Fixed a layer comparison issue causing false warnings to appear during layer operations. [#173](https://github.com/mitre-attack/mitreattack-python/issues/173).

# v3.0.4 - 4/23/2024

## Features

- Update release information for ATT&CK 15.0

# v3.0.3 - 3/13/2024

## Features

- Added support for searching relationships by content in `get_objects_by_content.py`. [#164](https://github.com/mitre-attack/mitreattack-python/pull/164)
- Updated copyright year.
- Add font size parameter to svg config. [#160](https://github.com/mitre-attack/mitreattack-python/issues/160)

## Fixes

- Fixed the placement of the grey subtechnique bars in `svg_objects.py`. [#166](https://github.com/mitre-attack/mitreattack-python/issues/166)
- Fixed readthedocs build.
- Fixed bug where self.src wasn't iterable in `get_objects_by_content()`.

# v3.0.2 - 11/22/2023

## Fixes

- Add mobile datasources to excel output.

# v3.0.1 - 11/14/2023

## Features

- Update release information for ATT&CK 14.1

## Fixes

- Fix logic for finding deprecated ATT&CK objects in `changelog_helper.py`.

# v3.0.0 - 10/31/2023

## Features

- Added support for Assets to the `MitreAttackData`, `attackToExcel`, `diffStix`, and `navlayers` modules.
- Updated `navlayers` module to support Navigator Layer File Format version 4.5. [#98](https://github.com/mitre-attack/mitreattack-python/issues/98)

# v2.1.1 - 10/18/2023

## Fixes

- Set all columns in Excel files Relationships tabs the same. [#136](https://github.com/mitre-attack/mitreattack-python/issues/136)

## Features

- mitreattack.stix20.MitreAttackData can now be initialized with a stix2.MemoryStore instead of just a STIX file.

# v2.1.0 - 10/13/2023

## Fixes

- Addressed issue in mitreattack/stix20/MitreAttackData.py which was causing duplicate Group entries. [#149](https://github.com/mitre-attack/mitreattack-python/issues/149)
- Updated toSvg() to address an underlying Pillow update. [#140](https://github.com/mitre-attack/mitreattack-python/issues/140)
- Fixed issue that caused some relationships to be excluded from the results. [#128](https://github.com/mitre-attack/mitreattack-python/issues/128)

## Documentation

- Updated documentation to include links to all the latest example scripts.

# v2.0.14 - 6/30/2023

## Fixes

- Downloading STIX in changelog_helper is more resilient

# v2.0.13 - 6/9/2023

## Fixes

- Fix issue with minimum version of drawsvg in setup.py

# v2.0.12 - 6/9/2023

## Features

- Changelog Helper: Ignore order when creating diff
- Changelog Helper: Attempt to download STIX multiple times

# v2.0.11 - 5/9/2023

## Features

- Update release information for ATT&CK 13.1

# v2.0.10 - 4/25/2023

## Features

- Add ATT&CK v13.0 release SHA256 hashes

# v2.0.9 - 4/23/2023

## Fixes

- Update sorting logic for detections and mitigations in changelog JSON format

# v2.0.8 - 4/20/2023

## Fixes

- Fix logic error for handling versions of ATT&CK objects in changelog helper

# v2.0.7 - 4/18/2023

## Fixes

- [Fix bug in get_all_software_used_by_all_groups()](https://github.com/mitre-attack/mitreattack-python/pull/109) (Credit: @jmsarn)
- Update categories for changelog helper script

# v2.0.6 - 3/13/2023

## Fixes

- Fix issue with getting revoked STIX objects

# v2.0.5 - 3/6/2023

## Fixes

- Fix dependency on drawSvg, pinning it to <2.0.0

# v2.0.4 - 1/30/2023

## Features

- Add functionality to `mitreattack/diffStix/changelog_helper.py` to provide changed Mitigations and Detections.

## Docs

- Add full docstrings to most functions in `mitreattack/diffStix/changelog_helper.py`.

# v2.0.3 - 1/23/2023

## Features

- Add `download_attack_stix` command that allows you to quickly download ATT&CK releases

## Fixes

- Fix an issue in the navlayers module where the legend is not generated in the SVG export when `SVGConfig.legendDocked=false` [#99](https://github.com/mitre-attack/mitreattack-python/pull/99)
- Fix Unicode display issue on detailed changelog page
- Tests now run against local STIX files instead of TAXII server, speeding them up drastically

## Docs

- Fix links to example scripts [#100](https://github.com/mitre-attack/mitreattack-python/pull/100)

# v2.0.2 - 1/10/2023

## Fixes

- Fix issue with diff_stix entrypoint when using the mitre/cti repository as the upstream source

# v2.0.1 - 1/10/2023

## Fixes

- Fix issue with Excel generation for Tactic names.

# v2.0.0 - 1/10/2023

## Fixes

- Fix Tactic names on Technique worksheets in exported Excel workbooks [#96](https://github.com/mitre-attack/mitreattack-python/issues/96)
- Fix exported Excel workbooks to include data source information about the ICS domain [#97](https://github.com/mitre-attack/mitreattack-python/issues/97)

## Improvements

- [Breaking change] Improve the changelog helper to produce much more granular details as needed [#79](https://github.com/mitre-attack/mitreattack-python/issues/79)
- Add a new library module, `MitreAttackData`, for working with ATT&CK data, including the functions and relationships microlibrary from the
[CTI USAGE document](https://github.com/mitre/cti/blob/master/USAGE.md). [#90](https://github.com/mitre-attack/mitreattack-python/issues/90)

# v1.7.3 - 12/6/2022

## Fixes

- Fix SVG export to hide disabled techniques when hideDisabled is True [#89](https://github.com/mitre-attack/mitreattack-python/issues/89)
- Fix SVG export to display platforms and legend items
- Fix parsing of link dividers in layer files [#94](https://github.com/mitre-attack/mitreattack-python/issues/94)
- Fix issue with retrieving technique ATT&CK IDs when generating a Navigator layer from the taxii server [#82](https://github.com/mitre-attack/mitreattack-python/issues/82)

# v1.7.2 - 10/24/2022

## Fixes

- Fix data component parsing in diffStix changelog script

# v1.7.1 - 10/23/2022

## Fixes

- Fix JSON support for diffStix changelog script

# v1.7.0 - 10/21/2022

## Improvements

- Add support for campaigns to the diffStix changelog script [#93](https://github.com/mitre-attack/mitreattack-python/pull/93)

# v1.6.2 - 9/7/2022

## Fixes

- Fix SVG export functionality [#74](https://github.com/mitre-attack/mitreattack-python/issues/74)

# v1.6.1 - 9/7/2022

## Fixes

- Finish switching from `outputDir` to `output_dir` (the breaking change broke ourselves! But this itself isn't a breaking change)

# v1.6.0 - 9/7/2022

## Fixes

- Fix Excel file generation for previous ATT&CK versions [#88](https://github.com/mitre-attack/mitreattack-python/issues/88)

## Misc

- Changed attackToExcel's `write_excel()` and `export()` function parameters to use snake case instead of camel case (`outputDir` became `output_dir`)

# v1.5.10 - 8/24/2022

## Misc

- Fix GitHub Actions pipeline to be able to publish to PyPI

# v1.5.9 - 8/24/2022

## Fixes

- Releasing a new version due to broken 1.5.8 package deployed from modified development environment

## Misc

- GitHub Actions now publish releases from tags instead of from local development environments
- Autoformatted code with black, and set up flake8 to lint as a GitHub Action going forward

# v1.5.8 - 8/23/2022

## Fixes

- Fix ability to construct SVG files from TAXII data [#76](https://github.com/mitre-attack/mitreattack-python/issues/76)
- Filter subtechniques in platforms in attacktoexcel [#84](https://github.com/mitre-attack/mitreattack-python/issues/84)

# v1.5.7 - 5/2/2022

## Fixes

- Gracefully handle missing kill chain phases

# v1.5.6 - 4/24/2022

## Fixes

- Fix Excel parsing for x-data-components

# v1.5.5 - 4/23/2022

## Fixes

- Fix logic error in Excel export when exporting from local file

# v1.5.4 - 4/23/2022

## Improvements

- Allow Excel to be exported from local STIX file without needing to download from GitHub

# v1.5.3 - 4/15/2022

## Fixes

- Fix Excel output for datasources/components to display correctly

# v1.5.2 - 4/13/2022

## Fixes

- Handle issue where there is a missing revoked relationship in the new STIX bundle

# v1.5.1 - 4/13/2022

## Improvements

- Make diffStix compatible back to python 3.5

# v1.5.0 - 4/12/2022

## Improvements

- Add diffStix module to be able to generate changelogs between different STIX bundles

# v1.4.6 - 3/25/2022

## Improvements

- Improved efficency of Excel generation capability

# v1.4.5 3/9/2022

## Fixes

- Patched core layer code to properly store 8-hex colors
- Patched core layer code to properly handle non-ascii characters when ingesting text
- Patched core layer code to properly initialize layers during instantiation
- Patched core layer code to properly support Metadata, MetaDiv, Link, LinkDiv instantiation
- Added storage support for transparency in gradient colors (rendering support will follow)
- Library now supports unicode characters in layers (UTF-16)

# v1.4.4 - 2/22/2022

## Fixes

- Patched core layer code to support minor changes in the 4.3 layer format

# v1.4.3 - 2/16/2022

## Improvements

- Added documentation regarding Release process
- Added documentation regarding Contributing
- Added standard test framework

## Fixes

- Fixed tactic parsing in AttackToExcel so tactics are capitalized correctly in the output (Command and Control instead of Command And Control)
- Corrected minor mistakes in the README documentation of some cli scripts

# v1.4.2 - 1/11/2022

## Improvements

- Added support for multiple CAPEC IDs for a single technique in AttackToExcel
- Tweaked AttackToExcel permissions sorting
- Added parsing for all technique permissions in AttackToExcel
- Added support for [ATT&CK Layer format 4.3](https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_3.md)

# v1.4.1 - 12/17/2021

## Improvements

- Added support for ATT&CK Workbench as a datasource
- Added parsing for CAPEC IDs in AttackToExcel
- Added support for data sources and data components when generating layers
- Added parsing for relationship references/citations in AttackToExcel

# v1.4.0 - 10/21/2021

## Fixes

- Updated stix2 and taxii2-client module version requirements to avoid potential bug

## Improvements

- Created Collections module
- Added method and cli to turn a collection index into a markdown file for human readability
- Added method and cli to turn a collection into a collection index for summary purposes
- Added method and cli to turn raw stix data into a collection
- Added method and cli to allow for bulk layer generation (expands generator module)
- Added Data Sources and Data Components support to attackToExcel

# v1.3.1 - 9/22/2021

Minor release that downgrades the required version of taxii2-client to 2.2.2 due to a bug in 2.3.0.

# v1.3.0 - 8/20/2021

This release introduces generator functionality to the library, as well as some improvements to excel matrix generation
through attackToExcel.

## Fixes

- Addresses potential import issues for some operating systems

## Improvements

- Updated attackToExcel to include platform information when generating excel matrices
- Added layer generation capabilities to the library
- Added a cli integration for the layer generation capabilities

# v1.2.2 - 7/27/2021

This bug fix patches a few outstanding issues with the library

## Fixes

- Added missing fields to attackToExcel technique output:
  - Enterprise: _Impact Type_, _System Requirements_, _Effective Permissions_
  - Mobile: _Tactic Type_
- Fixed typing mismatch in layerobj that caused issues with manipulator scripting
- Fixed potential loading issue with enumeration that could cause issues with manipulator scripting
- Improved error message handling during layer initialization

# v1.2.1 - 16 June 2021

This bug fix patches the ability to use the library with local data sources

## Fixes

- Addressed issue with matrixGen initialization failing for local data sources

# v1.2.0 - 2 June 2021

This update adds some convenience features to make it easier to create layers programmatically, as well
as documentation on how to do so.

## Improvements

- Made it possible to directly initialize Layer objects in core
- Created README documenting how to create layers programmatically through various approaches

# v1.1.0 - 29 April 2021

With the release of the ATT&CK Navigator Layer version 4.2, this library now supports the new
aggregateScore functionality and associated format changes.

## Improvements

- Added Layer format v4.2 compatibility.
- Added aggregateScore functionality to both the svg and excel exporting modules.
- Updated exporting modules and their initialization arguments to utilize copies of provided input layers.
- Added filtering functionality based on Platforms when generating a Matrix during export.

## Fixes

- Addressed issue with attackToExcel imports failing in some environments.
