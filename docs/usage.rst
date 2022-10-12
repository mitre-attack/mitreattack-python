Usage
==============================================

Installation
----------------------------------------------

To use this package, install the mitreattack-python library with `pip`_:

.. code-block:: shell

   pip install mitreattack-python

*Note*: the library requires `python3`_.


Additional Modules Overview
----------------------------------------------

More detailed information and examples about the specific usage of the additional modules in this 
package can be found in the individual README files for each module linked below.

.. list-table::
   :widths: 10 35 15
   :header-rows: 1
   :align: left

   * - module
     - description
     - documentation

   * - `navlayers`_
     - A collection of utilities for working with `ATT&CK Navigator`_  layers. Provides the ability to import, export, and manipulate layers. Layers can be read in from the filesystem or python dictionaries, combined and edited, and then exported to excel or SVG images.
     - Further documentation can be found in the `navlayers README`_.
   * - `attackToExcel`_
     - A collection of utilities for converting `ATT&CK STIX data`_ to Excel spreadsheets. It also provides access to `Pandas`_ DataFrames representing the dataset for use in data analysis. 
     - Further documentation can be found in the `attackToExcel README`_.
   * - `collections`_
     - A set of utilities for working with `ATT&CK Collections and Collection Indexes`_. Provides functionalities for converting and summarizing data in collections and collection indexes, as well as generating a collection from a raw stix bundle input.
     - Further documentation can be found in the `collections README`_.
   * - `diffStix`_
     - Create markdown, HTML, JSON and/or ATT&CK Navigator layers reporting on the changes between two versions of the STIX2 bundles representing the ATT&CK content. Run 'diff_stix -h' for full usage instructions.
     - Further documentation can be found in the `diffStix README`_.

.. _pip: https://pip.pypa.io/en/stable/
.. _python3: https://www.python.org/
.. _navlayers: https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/navlayers
.. _ATT&CK Navigator: https://github.com/mitre-attack/attack-navigator
.. _navlayers README: https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/README.md
.. _attackToExcel: https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/attackToExcel
.. _ATT&CK STIX data: https://github.com/mitre/cti
.. _Pandas: https://pandas.pydata.org/
.. _attackToExcel README: https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/attackToExcel/README.md
.. _collections: https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/collections
.. _ATT&CK Collections and Collection Indexes: https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md
.. _collections README: https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/collections/README.md
.. _diffStix: https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/diffStix
.. _diffStix README: https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/diffStix/README.md