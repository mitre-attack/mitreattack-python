# mitreattack-python

This repository contains a library of Python-based tools and utilities for working with ATT&CK content.

- the [navlayers](https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/navlayers) module
  contains a collection of utilities for working with [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) layers.
- the [attackToExcel](https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/attackToExcel) module
  provides utilities for converting [ATT&CK STIX data](https://github.com/mitre/cti) to Excel spreadsheets.
  It also provides access to [Pandas](https://pandas.pydata.org/) DataFrames representing the dataset for use in data analysis.
- the [collections](https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/collections) module
  contains a set of utilities for working with [ATT&CK Collections and Collection Indexes](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md).
- the [diffStix](https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/diffStix) module
  contains a script that generates changelogs between two versions of STIX bundles.
- the [attackObjects](https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/attackObjects) module contains a set of utilities for working with ATT&CK relationship objects.

## Requirements

- [python3](https://www.python.org/)

## Installation

To use this package, simply install the mitreattack-python library:

```shell
pip install mitreattack-python
```

## Contributing

To contribute to this project, either through a bug report, feature request, or merge request,
please see the [Contributors guide](https://github.com/mitre-attack/mitreattack-python/docs/CONTRIBUTING.MD).

## Usage

Some simple examples are provided here to get you started on using this library.
More detailed information about the specific usage of the modules in this package,
with examples, can be found in the individual README files for each module.

| module name | description | documentation |
|:------------|:------------|:--------------|
| navlayers | Provides a means by which to import, export, and manipulate [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) layers. These layers can be read in from the filesystem or python dictionaries, combined and edited, and then exported to excel or SVG images as users desire. | Further documentation for the navlayers module can be found [here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/README.md).|
| attackToExcel | Provides functionalities for exporting the ATT&CK dataset into Excel Spreadsheets. It also provides programmatic access to the dataset as [Pandas](https://pandas.pydata.org/) DataFrames to enable data analysis using that library. | Further documentation for the attackToExcel module can be found [here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/attackToExcel/README.md).|
| collections | Provides functionalities for converting and summarizing data in collections and collection indexes. It also provides a means by which to generate a collection from a raw stix bundle input. | Further documentation for the collections module can be found [here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/collections/README.md).|
| diffStix | Create markdown, HTML, JSON and/or ATT&CK Navigator layers reporting on the changes between two versions of the STIX2 bundles representing the ATT&CK content. Run `diff_stix -h` for full usage instructions. | Further documentation for the diffStix module can be found [here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/diffStix/README.md).|
| attackObjects | Provides functionality to build lookup tables of stixID to related objects and relationships. | Further documentation of the attackObjects module can be found [here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/attackObjects/README.md).|

### Usage Examples

#### navlayers

```python
from mitreattack.navlayers import Layer

example_layer4_dict = {
    "name": "layer v4.3 example",
    "versions" : {
        "attack": "8",
        "layer" : "4.3",
        "navigator": "4.3"
    },
    "domain": "enterprise-attack"
}

layerA = Layer()                                  # Create a new layer object
layerA.from_dict(example_layer4_dict)             # Load layer data into existing layer object
print(layerA.to_dict())                           # Retrieve the loaded layer's data as a dictionary, and print it
```

```python
from mitreattack.navlayers import Layer, ToSvg

lay = Layer()
lay.from_file("path/to/layer/example.json")           # import a layer from the filesystem

t = ToSvg(domain=lay.layer.domain, source='taxii')    # Use taxii server to get data for template
t.to_svg(lay, filepath="example.svg")           # render the layer to an SVG file
```

Further documentation for the navlayers module can be found [here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/README.md).

#### attackToExcel

```python
import mitreattack.attackToExcel.attackToExcel as attackToExcel

# generate spreadsheets representing enterprise-attack v8.1
attackToExcel.export("enterprise-attack", "v8.1", "/path/to/export/folder")
```

```python
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf

# download and parse ATT&CK STIX data
attackdata = attackToExcel.get_stix_data("enterprise-attack")
# get Pandas DataFrames for techniques, associated relationships, and citations
techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack") 

# show T1102 and sub-techniques of T1102
techniques_df = techniques_data["techniques"]
print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])
```

Further documentation for the attackToExcel module can be found
[here](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/attackToExcel/README.md).

#### Command Line Tools

Several command line tools have been included in this package.
They can be run immediately after installing the package, using the syntax described below.

##### layerExporter_cli

This command line tool allows users to convert a [navigator](https://github.com/mitre-attack/attack-navigator)
layer file to either an svg image or excel file using the functionality provided by the navlayers module.
Details about the SVG configuration json mentioned below can be found in the
[SVGConfig](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/README.md#svgconfig)
entry within the navlayers module documentation.

```commandline
C:\Users\attack>layerExporter_cli -h
usage: layerExporter_cli [-h] -m {svg,excel} [-s {taxii,local,remote}]
                            [--resource RESOURCE] -o OUTPUT [OUTPUT ...]
                            [-l LOAD_SETTINGS] [-d WIDTH HEIGHT]
                            input [input ...]

Export an ATT&CK Navigator layer as a svg image or excel file

positional arguments:
  input                 Path(s) to the file to export

optional arguments:
  -h, --help            show this help message and exit
  -m {svg,excel}, --mode {svg,excel}
                        The form to export the layers in
  -s {taxii,local,remote}, --source {taxii,local,remote}
                        What source to utilize when building the matrix
  --resource RESOURCE   Path to the local resource if --source=local, or url
                        of an ATT&CK Workbench instance if --source=remote
  -o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]
                        Path(s) to the exported svg/xlsx file
  -l LOAD_SETTINGS, --load_settings LOAD_SETTINGS
                        [SVG Only] Path to a SVG configuration json to use
                        when rendering
  -d WIDTH HEIGHT, --size WIDTH HEIGHT
                        [SVG Only] X and Y size values (in inches) for SVG
                        export (use -l for other settings)
                        
C:\Users\attack>layerExporter_cli -m svg -s taxii -l settings/config.json -o output/svg1.json output/svg2.json files/layer1.json files/layer2.json       
```

##### attackToExcel_cli

This command line tool allows users to generate excel spreadsheets representing the ATT&CK dataset.

```commandline
C:\Users\attack>attackToExcel_cli -h
usage: attackToExcel_cli [-h]
                         [-domain {enterprise-attack,mobile-attack,ics-attack}]
                         [-version VERSION] [-output OUTPUT]

Download ATT&CK data from MITRE/CTI and convert it to excel spreadsheets

optional arguments:
  -h, --help            show this help message and exit
  -domain {enterprise-attack,mobile-attack,ics-attack}
                        which domain of ATT&CK to convert
  -version VERSION      which version of ATT&CK to convert. If omitted, builds
                        the latest version
  -output OUTPUT        output directory. If omitted writes to a subfolder of
                        the current directory depending on the domain and
                        version
                        
C:\Users\attack>attackToExcel_cli -domain ics-attack -version v8.1 -output exported_data
```

##### layerGenerator_cli

This command line tool allows users to generate [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
layer files from either a specific group, software, or mitigation. Alternatively, users can generate a layer file with a
mapping to all associated groups, software, or mitigations across the techniques within ATT&CK.

```commandline
C:\Users\attack>layerGenerator_cli -h
usage: layerGenerator_cli [-h]
                             (--overview-type {group,software,mitigation,datasource} | --mapped-to MAPPED_TO | --batch-type {group,software,mitigation,datasource})
                             [-o OUTPUT] [--domain {enterprise,mobile,ics}]
                             [--source {taxii,local,remote}]
                             [--resource RESOURCE]

Generate an ATT&CK Navigator layer

optional arguments:
  -h, --help            show this help message and exit
  --overview-type {group,software,mitigation,datasource}
                        Output a layer file where the target type is
                        summarized across the entire dataset.
  --mapped-to MAPPED_TO
                        Output layer file with techniques mapped to the given
                        group, software, mitigation, or data component. Argument 
                        can be name, associated group/software, or ATT&CK ID.
  --batch-type {group,software,mitigation,datasource}
                        Output a collection of layer files to the specified
                        folder, each one representing a different instance of
                        the target type.
  -o OUTPUT, --output OUTPUT
                        Path to the output layer file/directory
  --domain {enterprise,mobile,ics}
                        Which domain to build off of
  --source {taxii,local,remote}
                        What source to utilize when building the layer files
  --resource RESOURCE   Path to the local resource if --source=local, or url
                        of an ATT&CK Workbench instance if --source=remote
  
C:\Users\attack>layerGenerator_cli --domain enterprise --source taxii --mapped-to S0065 --output generated_layer.json
C:\Users\attack>layerGenerator_cli --domain mobile --source taxii --overview-type mitigation --output generated_layer2.json
C:\Users\attack>layerGenerator_cli --domain ics --source taxii --batch-type software
C:\Users\attack>layerGenerator_cli --domain enterprise --source taxii --overview-type datasource --output generated_layer3.json
```

##### IndexToMarkdown_cli

This command line tool allows users to transform an
[ATT&CK collection index file](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes)
into a [human-readable markdown file](https://github.com/mitre-attack/attack-stix-data/blob/master/index.md) that
documents the contents of said collections.

```commandline
C:\Users\attack>indexToMarkdown_cli -h
usage: index_to_markdown.py [-h] [-index INDEX] [-output OUTPUT]

Print a markdown string to std-out representing a collection index

optional arguments:
  -h, --help      show this help message and exit
  -i INDEX, --index INDEX    the collection index file to convert to markdown
  -o output, --output OUTPUT  markdown output file
C:\Users\attack>indexToMarkdown_cli --index C:\Users\attack\examples\index.json --output example.md
```

##### CollectionToIndex_cli

This command line tool allows users to transform
[ATT&CK collections](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections)
into an [ATT&CK collection index](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes)
that summarizes the contents of the linked collections.

```commandline
C:\Users\attack>collectionToIndex_cli -h
usage: collection_to_index.py [-h] [--output OUTPUT]
                              (--files collection1 [collection2 ...] | --folders FOLDERS [FOLDERS ...])
                              name description root_url

Create a collection index from a set of collections

positional arguments:
  name                  name of the collection index. If omitted a placeholder
                        will be used
  description           description of the collection index. If omitted a
                        placeholder will be used
  root_url              the root URL where the collections can be found.
                        Specified collection paths will be appended to this
                        for the collection URL

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT        filename for the output collection index file
  --files collection1 [collection2 ...]
                        list of collections to include in the index
  --folders FOLDERS [FOLDERS ...]
                        folder of JSON files to treat as collections
C:\Users\attack>collectionToIndex_cli test_index "a layer created as a demo" www.example.com --files C:\Users\attack\examples\collection.json --output C:\Users\attack\examples\index.json
```

##### StixToCollection_cli

This command line tool allows users to transform raw stix bundle files into versions featuring
[collection](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections) objects.
It is compatible with both STIX 2.0 and STIX 2.1 bundles.

```commandline
C:\Users\attack>stixToCollection_cli -h
usage: stix_to_collection.py [-h] [--input INPUT] [--output OUTPUT]
                             [--description DESCRIPTION]
                             name version

Update a STIX 2.0 or 2.1 bundle to include a collection object referencing the
contents of the bundle.

positional arguments:
  name                  the name for the generated collection object
  version               the ATT&CK version for the generated collection object

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT          the input bundle file
  --output OUTPUT        the output bundle file
  --description DESCRIPTION
                        description to use for the generated collection

C:\Users\attack>stixToCollection "2.0 demo bundle" 9.1 --input C:\Users\bundles\enterprise-bundle-2_0.json
C:\Users\attack>stixToCollection "2.1 demo bundle" 9.1 --input C:\Users\bundles\enterprise-bundle-2_1.json
```

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

### ATT&CK scripts

One-off scripts and code examples you can use as inspiration for how to work with ATT&CK programmatically. Many of the functionalities found in the mitreattack-python package were originally posted on attack-scripts.

<https://github.com/mitre-attack/attack-scripts>

## Notice

Copyright 2021 The MITRE Corporation

Approved for Public Release; Distribution Unlimited. Case Number 19-0486.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
