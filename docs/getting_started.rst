
Getting started
==============================================

This repository houses the ATT&CK catalog's Cyber Threat Intelligence, represented in the STIX 2.0 JSON format. 
Additionally, it includes a USAGE document that provides further examples for accessing and parsing our dataset using Python.

Install
-----

To use this package, install the mitreattack-python library with `pip <https://pip.pypa.io/en/stable/>`_ :

.. code:: bash

   pip install mitreattack-python


Note: the library requires `python3 <https://www.python.org/>`_.

MitreAttackData Library
------------------------

The ``MitreAttackData`` library is used to read in and work with MITRE ATT&CK STIX 2.0 content. This library provides 
the ability to query the dataset for objects and their related objects. This is the main content of mitreattack-python;
you can read more about other modules in this library under the "Additional Modules" header in the side pane.

Additional Modules
------------------------

More detailed information and examples about the specific usage of the additional modules in this package can be found in the individual documents for each module linked below.


.. list-table::  
   :widths: 33 33 34
   :header-rows: 1

   * - module
     - description
     - documentation
   * - `navlayers <https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/navlayers>`_
     -  A collection of utilities for working with `ATT&CK Navigator <https://github.com/mitre-attack/attack-navigator>`_ layers. Provides the ability to import, export, and manipulate layers. Layers can be read in from the filesystem or python dictionaries, combined and edited, and then exported to excel or SVG images.
     -  Further documentation can be found `here <https://mitreattack-python.readthedocs.io/en/126-docs-add-section-to-docs-for-accessing-stix/navlayers.html>`_ 
   * - `attackToExcel <https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/attackToExcel>`_
     - A collection of utilities for converting `ATT&CK STIX data <https://github.com/mitre/cti>`_ to Excel spreadsheets. It also provides access to `Pandas <https://pandas.pydata.org/>`_ DataFrames representing the dataset for use in data analysis. 
     - Further documentation can be found `here <https://mitreattack-python.readthedocs.io/en/126-docs-add-section-to-docs-for-accessing-stix/attacktoexcel.html>`_
   * - `collections <https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/collections>`_
     - A set of utilities for working with `ATT&CK Collections and Collection Indexes <https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md>`_. Provides functionalities for converting and summarizing data in collections and collection indexes, as well as generating a collection from a raw stix bundle input. 
     - Further documentation can be found `here <https://mitreattack-python.readthedocs.io/en/126-docs-add-section-to-docs-for-accessing-stix/collections.html>`_.
   * - `diffStix <https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/diffStix>`_
     -   Create markdown, HTML, JSON and/or ATT&CK Navigator layers reporting on the changes between two versions of the STIX2 bundles representing the ATT&CK content. Run ``diff_stix -h`` for full usage instructions. 
     - Further documentation can be found `here <https://mitreattack-python.readthedocs.io/en/126-docs-add-section-to-docs-for-accessing-stix/diffinstix.html>`_


Related MITRE Work
------------------------

Go to `this link <https://mitreattack-python.readthedocs.io/en/latest/related_work.html>`_ for related MITRE work.


Contributing
------------------------

To contribute to this project, either through a bug report, feature request, or merge request,
please see the `Contributors Guide <https://github.com/mitre-attack/mitreattack-python/blob/master/docs/CONTRIBUTING.md>`_.

Notice
------------------------

Copyright 2023 The MITRE Corporation

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

`ATT&CK Terms of Use <https://attack.mitre.org/resources/terms-of-use/>`_
