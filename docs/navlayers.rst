NavLayers
==============================================

This folder contains modules and scripts for working with ATT&CK Navigator layers.
ATT&CK Navigator Layers are a set of annotations overlaid on top of the ATT&CK Matrix.
For more about ATT&CK Navigator layers, visit the ATT&CK Navigator repository.
The core module allows users to load, validate, manipulate, and save ATT&CK layers.
A brief overview of the components can be found below.
All scripts adhere to the MITRE ATT&CK Navigator Layer file format,
`version 4.3 <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_3.md>`_,
but will accept legacy `version 3.0 <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv3.md>`_
and version 4.X layers, upgrading them to version 4.3.

**Core Modules**


## Core Modules

.. list-table:: Title
   :widths: 25 25 50
   :header-rows: 1

   * - script
     - description
   * - `filter <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/filter.py>`_
     - Implements a basic `filter object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#filter-object-properties>`_
   * - `gradient <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/gradient.py>`_ 
     - Implements a basic `gradient object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#gradient-object-properties>`_
   * - `layer <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/layer.py>`_
     - Provides an interface for interacting with core module's layer representation. A further breakdown can be found in the corresponding [section](#Layer) below.
   * - `layout <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/layout.py>`_
     - Implements a basic `layout object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#layout-object-properties>`_
   * - `legenditem <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/legenditem.py>`_ 
     - Implements a basic `legenditem object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#legenditem-object-properties>`_
   * - `metadata <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/metadata.py>`_ 
     - Implements a basic `metadata object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#metadata-object-properties>`_
   * - `technique <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/technique.py>`_
     - Implements a basic `technique object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#technique-object-properties>`_
   * - `versions <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/versions.py>`_
     - Implements a basic `versions object <https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md#versions-object-properties>`_

**Manipulator Scripts

   * - script
     - description
   * - `layerops <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/manipulators/layerops.py>`_
     - Provides a means by which to combine multiple ATT&CK layer objects in customized ways. A further breakdown can be found in the corresponding [section](#layerops.py) below. 

**Exporter Scripts

   * - script
     - description
   * - `to_excel <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/exporters/to_excel.py>`_
     - Provides a means by which to export an ATT&CK Layer to an excel file. A further breakdown can be found in the corresponding [section](#to_excel.py) below.
   * - `to_svg <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/exporters/to_svg.py>`_
     - Provides a means by which to export an ATT&CK layer to an svg image file. A further breakdown can be found in the corresponding [section](#to_svg.py) below. This file also contains the `SVGConfig` object that can be used to configure the SVG export.



**Generator Scripts

   * - script
     - description
   * - `overview_generator <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/generators/overview_generator.py>`_
     - Provides a means by which to generate an ATT&CK Layer that summarizes, on a per technique basis, all instances of a given ATT&CK object type that reference/utilize each technique. A further explanation can be found in the corresponding [section](#overview_generator.py) below. 
   * - `usage_generator <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/generators/usage_generator.py>`_ 
     - Provides a means by which to generate an ATT&CK Layer that summarizes the techniques associated with a given ATT&CK object. A further explanation can be found in the corresponding [section](#usage_generator.py) below.
   * - `sum_generator <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/generators/sum_generator.py>`_ 
     - Provides a means by which to generate a collection of ATT&CK Layers, one for each object in a given ATT&CK object class, that summarizes the coverage of that object. A further explanation can be found in the corresponding [section](#sum_generator.py) below. 

**Utility Modules

   * - script
     - description
   * - `excel_templates <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/exporters/excel_templates.py>`_ 
     - Provides a means by which to convert a matrix into a clean excel matrix template. 
   * - `matrix_gen <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/exporters/matrix_gen.py>`_
     - Provides a means by which to generate a matrix from raw data, either from the ATT&CK TAXII server, from a local STIX Bundle, or from an ATT&CK Workbench instance (via url). 
   * - `svg_templates <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/exporters/svg_templates.py>`_
     - Provides a means by which to convert a layer file into a marked up svg file.
   * - `svg_objects <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/exporters/svg_objects.py>`_ 
     - Provides raw templates and supporting functionality for generating svg objects.

**Command Line Tools

   * - script
     - description
   * - `layerExporter_cli.py <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/layerExporter_cli.py>`_
     - A commandline utility to export Layer files to excel or svg formats using the exporter tools. Run with `-h` for usage. 
   * - `layerGenerator_cli.py <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/layerGenerator_cli.py>`_
     - A commandline utility to generate Layer files that correspond to various and collections of various stix objects. Run with `-h` for usage. 

**Layer

The `Layer` class provides format validation and read/write capabilities to aid in working with ATT&CK Navigator Layers in python.
It is the primary interface through which other Layer-related classes defined in the core module should be used.
The Layer class API and a usage example are below.
The class currently supports version 3 and 4 of the ATT&CK Layer spec, and will upgrade version 3 layers into compatible version 4 ones whenever possible.

   * - method [x = Layer()]
     - description
   * - `x.from_str(_input_)` 
     - Loads an ATT&CK layer from a string representation of a json layer.
   * - `x.from_dict(_input_)`
     - Loads an ATT&CK layer from a dictionary.
   * - `x.from_file(_filepath_)`
     - Loads an ATT&CK layer from a file location specified by the _filepath_.
   * - `x.to_file(_filepath_)`
     - Saves the current state of the loaded ATT&CK layer to a json file denoted by the _filepath_.
   * - `x.to_dict()`
     - Returns a representation of the current ATT&CK layer object as a dictionary. 
   * - `x.to_str()`
     - Returns a representation of the current ATT&CK layer object as a string representation of a dictionary.

Examples on how to create a layer programmatically, as opposed to loading it from an existing medium, can be found
`here <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/core/README.md>`_.

**Example Usage

.. code-block:: python
    example_layer3_dict = {
        "name": "example layer",
        "version": "3.0",
        "domain": "mitre-enterprise"
    }

    example_layer4_dict = {
        "name": "layer v4.3 example",
        "versions" : {
            "attack": "8",
            "layer" : "4.3",
            "navigator": "4.4.4"
        },
        "domain": "enterprise-attack"
    }

    example_layer_location = "/path/to/layer/file.json"
    example_layer_out_location = "/path/to/new/layer/file.json"

    from mitreattack.navlayers.core import Layer

    layer1 = Layer(example_layer3_dict)             # Create a new layer and load existing data
    layer1.to_file(example_layer_out_location)      # Write out the loaded layer to the specified file

    layer2 = Layer()                                # Create a new layer object
    layer2.from_dict(example_layer4_dict)           # Load layer data into existing layer object
    print(layer2.to_dict())                         # Retrieve the loaded layer's data as a dictionary, and print it

    layer3 = Layer()                                # Create a new layer object
    layer3.from_file(example_layer_location)        # Load layer data from a file into existing layer object


**layerops.py

`Layerops.py` provides the `LayerOps` class, which is a way to combine layer files in an automated way, using user defined lambda functions.
Each LayerOps instance, when created, ingests the provided lambda functions, and stores them for use.
An existing `LayerOps` class can be used to combine layer files according to the initialized lambda using the process method.
The breakdown of this two step process is documented in the table below, while examples of both the list and dictionary modes of operation can be found below.

**# LayerOps()

.. code-block:: python

    x = LayerOps(score=score, comment=comment, enabled=enabled, colors=colors, metadata=metadata, name=name, desc=desc, default_values=default_values)


Each of the _inputs_ takes a lambda function that will be used to combine technique object fields matching the parameter.
The one exception to this is _default_values_, which is an optional dictionary argument containing default values
to provide the lambda functions if techniques of the combined layers are missing them.

****.process() Method

.. code-block:: python
    x.process(data, default_values=default_values)


The process method applies the lambda functions stored during initialization to the layer objects in _data_.
_data_ must be either a list or a dictionary of Layer objects, and is expected to match the format of the lambda equations provided during initialization.
`default_values` is an optional dictionary argument that overrides the currently stored default values with new ones for this specific processing operation.

**# Example Usage

.. code-block:: python
    from mitreattack.navlayers.manipulators.layerops import LayerOps
    from mitreattack.navlayers.core.layer import Layer

    demo = Layer()
    demo.from_file("C:\Users\attack\Downloads\layer.json")
    demo2 = Layer()
    demo2.from_file("C:\Users\attack\Downloads\layer2.json")
    demo3 = Layer()
    demo3.from_file("C:\Users\attack\Downloads\layer3.json")

    # Example 1) Build a LayerOps object that takes a list and averages scores across the layers
    lo = LayerOps(score=lambda x: sum(x) / len(x),
                name=lambda x: x[1],
                desc=lambda x: "This is an list example")     # Build LayerOps object
    out_layer = lo.process([demo, demo2])                       # Trigger processing on a list of demo and demo2 layers
    out_layer.to_file("C:\demo_layer1.json")                    # Save averaged layer to file
    out_layer2 = lo.process([demo, demo2, demo3])               # Trigger processing on a list of demo, demo2, demo3
    visual_aid = out_layer2.to_dict()                           # Retrieve dictionary representation of processed layer

    # Example 2) Build a LayerOps object that takes a dictionary and averages scores across the layers
    lo2 = LayerOps(score=lambda x: sum([x[y] for y in x]) / len([x[y] for y in x]),
                colors=lambda x: x['b'],
                desc=lambda x: "This is a dict example")      # Build LayerOps object, with lambda
    out_layer3 = lo2.process({'a': demo, 'b': demo2})            # Trigger processing on a dictionary of demo and demo2
    dict_layer = out_layer3.to_dict()                            # Retrieve dictionary representation of processed layer
    print(dict_layer)                                            # Display retrieved dictionary
    out_layer4 = lo2.process({'a': demo, 'b': demo2, 'c': demo3})# Trigger processing on a dictionary of demo, demo2, demo3
    out_layer4.to_file("C:\demo_layer4.json")                    # Save averaged layer to file

    # Example 3) Build a LayerOps object that takes a single element dictionary and inverts the score
    lo3 = LayerOps(score=lambda x: 100 - x['a'],
                desc= lambda x: "This is a simple example")  # Build LayerOps object to invert score (0-100 scale)
    out_layer5 = lo3.process({'a': demo})                       # Trigger processing on dictionary of demo
    print(out_layer5.to_dict())                                 # Display processed layer in dictionary form
    out_layer5.to_file("C:\demo_layer5.json")                   # Save inverted score layer to file

    # Example 4) Build a LayerOps object that combines the comments from elements in the list, with custom defaults
    lo4 = LayerOps(score=lambda x: '; '.join(x),
                default_values= {
                    "comment": "This was an example of new default values"
                    },
                desc= lambda x: "This is a defaults example")  # Build LayerOps object to combine descriptions, defaults
    out_layer6 = lo4.process([demo2, demo3])                      # Trigger processing on a list of demo2 and demo0
    out_layer6.to_file("C:\demo_layer6.json")                     # Save combined comment layer to file


**to_excel.py

`to_excel.py` provides the `ToExcel` class, which is a way to export an existing layer file as an Excel spreadsheet.
The `ToExcel` class has an optional parameter for the initialization function, that tells the exporter what data source to use when building the output matrix.
Valid options include using live data from cti-taxii.mitre.org, using a local STIX bundle, or retrieving data from an ATT&CK Workbench instance.

**ToExcel()

.. code-block:: python
    x = ToExcel(domain='enterprise', source='taxii', resource=None)


The `ToExcel` constructor takes domain, server, and resource arguments during instantiation.
The domain can be either `enterprise` or `mobile`, and can be pulled directly from a layer file as `layer.domain`.
The source argument tells the matrix generation tool which data source to use when building the matrix.
`taxii` indicates that the tool should utilize the official ATT&CK Taxii Server (`cti-taxii`) when building the matrix,
while the `local` option indicates that it should use a local bundle, and the `remote` option indicates that
it should utilize a remote ATT&CK Workbench instance.
The `resource` argument is only required if the source is set to `local`, in which case it should be a path
to a local stix bundle, or if the source is set to `remote`, in which case it should be the url of a ATT&CK workbench instance.

**.to_xlsx() Method

.. code-block:: python
x.to_xlsx(layerInit=layer, filepath="layer.xlsx")
```

The `to_xlsx` method exports the layer file referenced as `layer`, as an excel file to the `filepath` specified.

**# Example Usage

.. code-block:: python
from mitreattack.navlayers import Layer
from mitreattack.navlayers import ToExcel

    lay = Layer()
    lay.from_file("path/to/layer/file.json")
    # Using taxii server for template
    t = ToExcel(domain=lay.layer.domain, source='taxii')
    t.to_xlsx(layerInit=lay, filepath="demo.xlsx")
    # Using local stix data for template
    t2 = ToExcel(domain='mobile', source='local', resource='path/to/local/stix.json')
    t2.to_xlsx(layerInit=lay, filepath="demo2.xlsx")
    # Using remote ATT&CK Workbench instance for template
    workbench_url = 'localhost:3000'
    t3 = ToExcel(domain='ics', source='remote', resource=workbench_url)


**to_svg.py

`to_svg.py` provides the `ToSvg` class, which is a way to export an existing layer file as an SVG image file.
The `ToSvg` class, like the `ToExcel` class, has an optional parameter for the initialization function,
that tells the exporter what data source to use when building the output matrix.
Valid options include using live data from cti-taxii.mitre.org, using a local STIX bundle, or utilizing a remote ATT&CK Workbench instance.

**ToSvg()

.. code-block:: python
    x = ToSvg(domain='enterprise', source='taxii', resource=None, config=None)


The `ToSvg` constructor, just like the `ToExcel` constructor, takes domain, server, and resource arguments during instantiation.
The domain can be either `enterprise` or `mobile`, and can be pulled directly from a layer file as `layer.domain`.
The source argument tells the matrix generation tool which data source to use when building the matrix.
`taxii` indicates that the tool should utilize the `cti-taxii` server when building the matrix,
while the `local` option indicates that it should use a local bundle, and the `remote` option indicates that it should utilize a remote ATT&CK Workbench instance.
The `resource` argument is only required if the source is set to `local`, in which case it should be a path to a local stix bundle,
or if the source is set to `remote`, in which case it should be the url of an ATT&CK Workbench instance.
The `config` parameter is an optional `SVGConfig` object that can be used to configure the export as desired.
If not provided, the configuration for the export will be set to default values.

**SVGConfig()

.. code-block:: python
    y = SVGConfig(width=8.5, height=11, headerHeight=1, unit="in", showSubtechniques="expanded",
                    font="sans-serif", tableBorderColor="#6B7279", showHeader=True, legendDocked=True,
                    legendX=0, legendY=0, legendWidth=2, legendHeight=1, showLegend=True, showFilters=True,
                    showAbout=True, showDomain=True, border=0.104)


The `SVGConfig` object is used to configure how an SVG export behaves.
The defaults for each of the available values can be found in the declaration above, and a brief explanation for each field is included in the table below.
The config object should be provided to the `ToSvg` object during instantiation, but if values need to be updated on the fly,
the currently loaded configuration can be interacted with at `ToSvg().config`.
The configuration can also be populated from a json file using the `.load_from_file(filename="path/to/file.json")` method,
or stored to one using the `.save_to_file(filename="path/to/file.json)` method.

   * - attribute
     - description
     - type
     - default value
   * - width 
     - Desired SVG width
     - number
     - 8.5
   * - height
     - Desired SVG height
     - number
     - 11
   * - headerHeight
     - Desired Header Block height
     - number
     - 1
   * - unit 
     - SVG measurement units (qualifies width, height, etc.) - "in", "cm", "px", "em", or "pt"
     - string 
     - "in" 
   * - showSubtechniques 
     - Display form for subtechniques - "all", "expanded" (decided by layer), or "none"
     - string 
     - "expanded" 
   * - font 
     - What font style to use - "serif", "sans-serif", or "monospace" 
     - string 
     - "sans-serif" 
   * - tableBorderColor 
     - Hex color to use for the technique borders 
     - string 
     - "#6B7279" 
   * - showHeader 
     - Whether or not to show Header Blocks 
     - bool 
     - True 
   * - legendDocked 
     - Whether or not the legend should be docked 
     - bool  
     - True 
   * - legendX 
     - Where to place the legend on the x axis if not docked 
     - number 
     - 0
   * - legendY 
     - Where to place the legend on the y axis if not docked 
     - number 
     - 1 
   * - legendWidth 
     - Width of the legend if not docked 
     - number 
     - 2 
   * - legendHeight 
     - Height of the legend if not docked 
     - number 
     - 1 
   * - showLegend 
     - Whether or not to show the legend 
     - bool 
     - True 
   * - showFilters 
     - Whether or not to show the Filter Header Block 
     - bool 
     - True 
   * - showDomain 
     - Whether or not to show the Domain and Version Header Block 
     - bool 
     - True 
   * - showAbout 
     - Whether or not to show the About Header Block 
     - bool 
     - True 
   * - border 
     - What default border width to use 
     - number 
     - 0.104 

**.to_svg() Method

.. code-block:: python
    x.to_svg(layerInit=layer, filepath="layer.svg")

The `to_svg` method exports the layer file referenced as `layer`, as an excel file to the `filepath` specified.

**# Example Usage

.. code-block:: python
    from mitreattack.navlayers import Layer
    from mitreattack.navlayers import ToSvg, SVGConfig

    lay = Layer()
    lay.from_file("path/to/layer/file.json")
    # Using taxii server for template
    t = ToSvg(domain=lay.layer.domain, source='taxii')
    t.to_svg(layerInit=lay, filepath="demo.svg")
    #Using local stix data for template

    conf = SVGConfig()
    conf.load_from_file(filename="path/to/poster/config.json")

    t2 = ToSvg(domain='mobile', source='local', resource='path/to/local/stix.json', config=conf)
    t2.to_svg(layerInit=lay, filepath="demo2.svg")

    workbench_url = "localhost:3000"
    t3 = ToSvg(domain='enterprise', source='remote', resource=workbench_url, config=conf)
    t3.to_svg(layerInit=lay, filepath="demo3.svg")


**overview_generator.py**

`overview_generator.py` provides the `OverviewLayerGenerator` class, which is designed to allow users to
generate an ATT&CK layer that, on a per technique basis, has a score that corresponds to all instances
of the specified ATT&CK object type (group, mitigation, etc.), and a comment that lists all matching instance.

**OverviewLayerGenerator()**

.. code-block:: python
    x = OverviewLayerGenerator(source='taxii', domain='enterprise', resource=None)


The initialization function for `OverviewLayerGenerator`, like `ToSVG` and `ToExcel`, requires the specification of where
to retrieve data from (taxii server etc.).
The domain can be either `enterprise`, `mobile`, or `ics`, and can be pulled directly from a layer file as `layer.domain`.
The source argument tells the matrix generation tool which data source to use when building the matrix.
`taxii` indicates that the tool should utilize the `cti-taxii` server when building the matrix,
while the `local` option indicates that it should use a local bundle, and the `remote` option indicates that it should utilize a remote ATT&CK Workbench instance.
The `resource` argument is only required if the source is set to `local`, in which case it should be a path to a local stix bundle,
or if the source is set to `remote`, in which case it should be the url of an ATT&CK Workbench instance.
If not provided, the configuration for the generator will be set to default values.

**.generate_layer()**

.. code-block:: python
    x.generate_layer(obj_type=object_type_name)


The `generate_layer` function generates a layer, customized to the input `object_type_name`.
Valid values include `group`, `mitigation`, `software`, and `datasource`.

**usage_generator.py**

`usage_ generator.py` provides the `UsageLayerGenerator` class, which is designed to allow users to
generate an ATT&CK layer that scores any relevant techniques that a given input ATT&CK object has.
These objects can be any `group`, `software`, `mitigation`, or `data component`,
and can be referenced by ID or by any alias when provided to the generator.

**UsageLayerGenerator()**

.. code-block:: python
    x = UsageLayerGenerator(source='taxii', domain='enterprise', resource=None)


The initialization function for `UsageLayerGenerator`, like `ToSVG` and `ToExcel`, requires the specification of where
to retrieve data from (taxii server etc.).
The domain can be either `enterprise`, `mobile`, or `ics`, and can be pulled directly from a layer file as `layer.domain`.
The source argument tells the matrix generation tool which data source to use when building the matrix.
`taxii` indicates that the tool should utilize the `cti-taxii` server when building the matrix,
while the `local` option indicates that it should use a local bundle, and the `remote` option indicates that it should utilize a remote ATT&CK Workbench instance.
The `resource` argument is only required if the source is set to `local`, in which case it should be a path to a local stix bundle,
or if the source is set to `remote`, in which case it should be the url of an ATT&CK Workbench instance.
If not provided, the configuration for the generator will be set to default values.

**.generate_layer()**

.. code-block:: python
    
    x.generate_layer(match=object_identifier)


The `generate_layer` function generates a layer, customized to the input `object_identifier`.
Valid values include `ATT&CK ID`, `name`, or any known `alias` for `group`, `mitigation`, `software`, and `data component` objects within the selected ATT&CK data.

.. code-block:: python

    from mitreattack.navlayers import UsageLayerGenerator

    handle = UsageLayerGenerator(source='taxii', domain='enterprise')

    layer1 = handle.generate_layer(match='G0018')
    layer2 = handle.generate_layer(match='Adups')


**sum_generator.py**

`sum_generator.py` provides the `SumLayerGenerator` class, which is designed to allow users to
generate a collection of ATT&CK layers that, on a per technique basis, have a score that corresponds to all instances
of the specified ATT&CK object type (group, mitigation, etc.), and a comment that lists all matching instance.
Each one of the generated layers will correspond to a single instance of the specified ATT&CK object type.

**SumLayerGenerator()**

.. code-block:: python
    
    x = SumLayerGenerator(source='taxii', domain='enterprise', resource=None)


The initialization function for `SumGeneratorLayer`, like `ToSVG` and `ToExcel`, requires the specification of where
to retrieve data from (taxii server etc.).
The domain can be either `enterprise`, `mobile`, or `ics`, and can be pulled directly from a layer file as `layer.domain`.
The source argument tells the matrix generation tool which data source to use when building the matrix.
`taxii` indicates that the tool should utilize the `cti-taxii` server when building the matrix,
while the `local` option indicates that it should use a local bundle, and the `remote` option indicates that it should utilize a remote ATT&CK Workbench instance.
The `resource` argument is only required if the source is set to `local`, in which case it should be a path to a local stix bundle,
or if the source is set to `remote`, in which case it should be the url of an ATT&CK Workbench instance.
If not provided, the configuration for the generator will be set to default values.

**.generate_layer()**

.. code-block:: python
    
    x.generate_layer(layers_type=object_type_name)


The `generate_layer` function generates a collection of layers, each customized to one instance of the input `object_type_name`.
Valid types include `group`, `mitigation`, `software`, and `datasource`.

**layerExporter_cli.py**

This command line tool allows users to convert a `navigator <https://github.com/mitre-attack/attack-navigator>`_
layer file to either an svg image or excel file using the functionality provided by the navlayers module.
Details about the SVG configuration json mentioned below can be found in the
`SVGConfig <https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/README.md#svgconfig>`_
entry within the navlayers module documentation.

.. code:: bash
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


**layerGenerator_cli.py**

This command line tool allows users to generate `ATT&CK Navigator <https://github.com/mitre-attack/attack-navigator>`_
layer files from either a specific group, software, or mitigation. Alternatively, users can generate a layer file with a
mapping to all associated groups, software, or mitigations across the techniques within ATT&CK.

.. code:: bash
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
