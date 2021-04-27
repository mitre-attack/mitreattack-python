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