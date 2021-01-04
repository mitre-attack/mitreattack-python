# mitreattack

This repository contains various tools and utilities for working with ATT&CK content.
- the [navlayers](mitreattack/navlayers/) module contains a collection of objects and scripts for working with [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) layers.
- the [attackToExcel](mitreattack/attackToExcel/) module contains a means to convert [ATT&CK STIX data](https://github.com/mitre/cti) to Excel spreadsheets. It also provides a [Pandas](https://pandas.pydata.org/) DataFrames method for
 analyzing and working with ATT&CK data.
- more coming soon!

## Requirements
- [python3](https://www.python.org/)

## Installation
To use this package, simply install the mitreattack-python library: 
```python
pip install mitreattack-python
``` 

## Usage
Some simple examples are provided here to get you started on using this library. More detailed information about the specific usage of the modules in this package, with examples, can be found in the individual README files for each module.

| module name | description | documentation |
|:------------|:------------|:--------------|
| navlayers | Provides a means by which to import, export, and manipulate ATT&CK Layer files. These layer files can be read in from files or python dictionaries, combined and edited, and then exported to excel or SVG images as users desire. | Further documentation for the navlayers module can be found [here](mitreattack/navlayers/README.md).|
| attackToExcel | Provides a means by which to convert the ATT&CK STIX data into Excel Spreadsheets. It also provides a means by data analysis can be performed on the data using Pandas dataframes. | Further documentation for the attackToExcel module can be found [here](mitreattack/attackToExcel/README.md).|
### Usage Examples
#### navlayers
```python
from mitreattack.navlayers import Layer

example_layer4_dict = {
    "name": "layer v4.1 example",
    "versions" : {
        "attack": "8",
        "layer" : "4.1",
        "navigator": "4.1"
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
lay.from_file("path/to/layer/file.json")

t = ToSvg(domain=lay.layer.domain, source='taxii') # Use taxii server for template
t.to_svg(layer=lay, filepath="demo.svg")           # Export 'file.json' ATT&CK layer to demo.svg SVG
```
#### attackToExcel
```python
from mitreattack import attackToExcel

attackToExcel.export("enterprise-attack", "v8.1", "/path/to/export/folder")
```

```python
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf

# download and parse ATT&CK STIX data
attackdata = attackToExcel.get_data_from_version("enterprise-attack")
techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")

# show T1102 and sub-techniques of T1102
techniques_df = techniques_data["techniques"]
print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])
```
## Related MITRE Work
#### CTI
[Cyber Threat Intelligence repository](https://github.com/mitre/cti) of the ATT&CK catalog expressed in STIX 2.0 JSON. This repository also contains [our USAGE document](https://github.com/mitre/cti/blob/master/USAGE.md) which includes additional examples of accessing and parsing our dataset in Python.

#### ATT&CK
ATT&CK® is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target. ATT&CK is useful for understanding security risk against known adversary behavior, for planning security improvements, and verifying defenses work as expected.

https://attack.mitre.org

#### STIX
Structured Threat Information Expression (STIX<sup>™</sup>) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

https://oasis-open.github.io/cti-documentation/

#### ATT&CK scripts
One-off scripts and code examples you can use as inspiration for how to work with ATT&CK programmatically. Many of the functionalities found in the mitreattack-python package were originally posted on attack-scripts.

https://github.com/mitre-attack/attack-scripts

## Notice

Copyright 2020 The MITRE Corporation

Approved for Public Release; Distribution Unlimited. Case Number 19-0486.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
