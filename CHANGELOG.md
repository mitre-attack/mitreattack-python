# v1.5.10 8/24/2022

## Misc

- Fix GitHub Actions pipeline to be able to publish to PyPI

# v1.5.9 8/24/2022

## Fixes

- Releasing a new version due to broken 1.5.8 package deployed from modified development environment

## Misc

- GitHub Actions now publish releases from tags instead of from local development environments
- Autoformatted code with black, and set up flake8 to lint as a GitHub Action going forward

# v1.5.8 8/23/2022

## Fixes

- Fix ability to construct SVG files from TAXII data [#76](https://github.com/mitre-attack/mitreattack-python/issues/76)
- Filter subtechniques in platforms in attacktoexcel [#84](https://github.com/mitre-attack/mitreattack-python/issues/84)

# v1.5.7 5/2/2022

## Fixes

- Gracefully handle missing kill chain phases

# v1.5.6 4/24/2022

## Fixes

- Fix Excel parsing for x-data-components

# v1.5.5 4/23/2022

## Fixes

- Fix logic error in Excel export when exporting from local file

# v1.5.4 4/23/2022

## Improvements

- Allow Excel to be exported from local STIX file without needing to download from GitHub

# v1.5.3 4/15/2022

## Fixes

- Fix Excel output for datasources/components to display correctly

# v1.5.2 4/13/2022

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
