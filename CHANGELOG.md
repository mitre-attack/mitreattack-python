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
