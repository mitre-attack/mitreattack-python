# Layers Core
This subcomponent, as part of the larger navlayers module, is responsible for Layer objects. Please note, this 
documentation assumes familiarity with the [ATT&CK Navigator layer format](https://github.com/mitre-attack/attack-navigator/blob/develop/layers/LAYERFORMATv4_1.md).
The main handle for this implementation is the Layer, which stores an individual instance of a LayerObj object,
which further references the various sub-objects that make up a complete Layer. A visual representation of this
object breakdown can be seen here (please note there are other fields, these are just the objects):
```
demo (Layer instance) <------------------------------------------------> The container for a layer object
  |---> demo.layer (_LayerObj instance)--------------------------------> The raw layer object itself
          |---> demo.layer.version (Versions instance)-----------------> A versions object
          |---> demo.layer.filters (Filter instance)-------------------> A filter object
          |---> demo.layer.layout (Layout instance)--------------------> A layout object
          |---> demo.layer.techniques (List of Technique instances)----> A collection of technique objects
          |---> demo.layer.gradient (Gradient instance)----------------> A gradient object
          |---> demo.layer.legendItems (List of LegendItem instances)--> A collection of legend item objects
          |---> demo.layer.metadata (List of Metadata instances)-------> A collection of metadata objects
```

## Creating Layers Programmatically
With knowledge of the objects involved, as well as the additional fields (which have a 1:1 mapping with the 
default ATT&CK Navigator spec), it is possible to programmatically generate a layer. Below is an example of
how this might be accomplished, piece by piece.

```python
import mitreattack.navlayers as navlayers

layer_example = navlayers.Layer()
layer_example.from_dict(dict(name="example", domain="enterprise-attack"))  # arguments required for every layer

# configure the versions object
layer_example.layer.versions = dict(layer="4.5", attack="15", navigator="5.0.0")

# set a description
layer_example.layer.description = "This is a demonstration of how to set up a layer piece by piece"

# configure the "filters" object
layer_example.layer.filters = dict(platforms=['macOS'])  # platforms can be provided during initialization
layer_example.layer.filters.platforms = ['Windows']  # or separately

# configure the 'sorting' setting
layer_example.layer.sorting = 3  # 0: sort ascending alphabetically by technique name
# 1: sort descending alphabetically by technique name
# 2: sort ascending by technique score
# 3: sort descending by technique score

# configure the layout object
layer_example.layer.layout = dict(layout="side",
                                  showID=True,
                                  showName=True,
                                  showAggregateScores=True,
                                  countUnscored=True,
                                  aggregateFunction="sum", # average, sum, max, min
                                  expandedSubtechniques="annotated")  # all, annotated, none

# configure whether or not to hide disabled techniques
layer_example.layer.hideDisabled = True
# configure the gradient object
layer_example.layer.gradient = dict(minValue=-100, maxValue=100,
                                    colors=["#DAF7A6", "#FFC300", "#FF5733", "#C70039", "#900C3F", "#581845"])
# configure collection of legend items 
layer_example.layer.legendItems = [dict(label='A', color='#DAF7A6'), dict(label='B', color='#581845')]
# configure collection of metatdata values
layer_example.layer.metadata = [dict(name='example metadata', value='This is an example')]
# create listing of techniques in this layer
layer_example.layer.techniques = [dict(techniqueID='T1000', tactic='privilege-escalation', score=15, color='#AABBCC'),
                                  dict(techniqueID='T1000.1', tactic='privilege-escalation', score=1, comment='Demo')]
```
This first example utilizes the native dictionary form for initializing the layer. This approach is similar to the 
method used by the automated import process, but may not be the most intuitive for users. An alternative method, 
displayed below, is to create and modify instances of the core objects in the library. Please note, these two examples 
produce equivalent internal layers once completed.

```python
import mitreattack.navlayers as navlayers

layer_example = navlayers.Layer(name="example", domain="enterprise-attack") # arguments required for every layer
layer_build = layer_example.layer  # short handle to make the rest of this example easier to read

# configure the versions object
versions_obj = navlayers.Versions()
versions_obj.layer = "4.2"
versions_obj.attack = "9.1"
versions_obj.navigator = "4.2"
layer_build.versions = versions_obj

# set a description
layer_build.description = "This is a demonstration of how to set up a layer piece by piece"

# configure the "filters" object
filter_obj = navlayers.core.Filter(domain="enterprise-attack")
filter_obj.platforms = ['Windows']
layer_build.filters = filter_obj

# configure the 'sorting' setting
layer_build.sorting = 3  # 0: sort ascending alphabetically by technique name
# 1: sort descending alphabetically by technique name
# 2: sort ascending by technique score
# 3: sort descending by technique score

# configure the layout object
layout_obj = navlayers.core.Layout()
layout_obj.layout = "side"
layout_obj.showID = True
layout_obj.showName = True
layout_obj.showAggregateScores = True
layout_obj.expandedSubtechniques = "annotated"
layout_obj.countUnscored = True
layout_obj.aggregateFunction = "sum"  # average, sum, max, min
layer_build.layout = layout_obj

# configure whether or not to hide disabled techniques
layer_build.hideDisabled = True

# configure the gradient object
gradient_obj = navlayers.core.Gradient(colors=["#DAF7A6", "#FFC300", "#FF5733", "#C70039", "#900C3F", "#581845"],
                                       minValue=-100, maxValue=100)
layer_build.gradient = gradient_obj

# configure collection of legend items
legend_item_obj_a = navlayers.core.LegendItem(label='A', color='#DAF7A6')
legend_item_obj_b = navlayers.core.LegendItem(label='B', color='#581845')
list_of_legend_items = [legend_item_obj_a, legend_item_obj_b]
layer_build.legendItems = list_of_legend_items

# configure collection of metatdata values
metadata_object = navlayers.core.Metadata(name='example metadata', value='This is an example')
layer_build.metadata = [metadata_object]

# create listing of techniques in this layer
technique_obj_a = navlayers.core.Technique(tID='T1000')
technique_obj_a.tactic = 'privilege-escalation'
technique_obj_a.score = 15
technique_obj_a.color = '#AABBCC'
technique_obj_b = navlayers.core.Technique(tID='T1000.1')
technique_obj_b.tactic = 'privilege-escalation'
technique_obj_b.score = 1
technique_obj_b.comment = "Demo"
layer_build.techniques = [technique_obj_a, technique_obj_b]

```

### Object Documentation
Should it be helpful, the following section provides a breakdown of the available fields and methods for 
each of the objects in the Core. This only includes 'public' methods and fields; there may be others used
for processing and other functionality that are not documented here, though documentation does exist for these
in the source code for them.

#### Layer Object
```python
    Layer().layer       # Stores the raw LayerObj file
    Layer().strict      # Determines whether or not to be strict about loading files
    Layer().from_str()  # Initializes data from a string
    Layer().from_dict() # Initializes data from a dictionary
    Layer().from_file() # Initializes data from a file
    Layer().to_file()   # Exports the layer data to a file
    Layer().to_dict()   # Exports the layer data to a dictionary
    Layer().to_str()    # Exports the layer data to a string
 ```
#### LayerObj Object
```python
    _LayerObj().versions                      # Link to a Versions object instance
    _LayerObj().name                          # The Name for the Layer
    _LayerObj().description                   # A description string for the Layer
    _LayerObj().domain                        # The domain for the Layer
    _LayerObj().filters                       # Link to a Filter object instance
    _LayerObj().sorting                       # An integer denoting which sorting form to use
    _LayerObj().layout                        # Link to a Layout object instance
    _LayerObj().hideDisabled                  # Bool determining whether or not to show disabled techniques
    _LayerObj().techniques                    # List of links to Technique objects
    _LayerObj().gradient                      # Link to Gradient object
    _LayerObj().legendItems                   # List of links to LegendItems objects
    _LayerObj().showTacticRowBackground       # Bool determining whether or not to show a background for tactics
    _LayerObj().tacticRowBackground           # Color code for tactic background
    _LayerObj().selectTechniquesAcrossTactics # Bool determining whether or not to select cross-tactic
    _LayerObj().selectSubtechniquesWithParent # Bool determining whether or not to select subtechniques
    _LayerObj().selectVisibleTechniques       # Bool determining whether or not to select only visible techniques
    _LayerObj().metadata                      # List of links to Metadata items
    _LayerObj().get_dict()                    # Export Layer as a dictionary object
```
#### Versions Object
```python
    Versions().layer      # String denoting Layer format version
    Versions().__attack   # String denoting ATT&CK version
    Versions().navigator  # String denoting Navigator version
    Versions().get_dict() # Export Version data as a dictionary object
```
#### Filter Object
```python
    Filter().domain     # String denoting the domain for the Filter
    Filter().platforms  # String denoting platforms within this filter
    Filter().get_dict() # Export Filter data as a dictionary object
```
Please note that although not documented here, there is another Filter object variant, Filterv3, which exists
for backwards compatibility reasons.
#### Layout Object
```python
    Layout().layout              # String denoting which layout form to use
    Layout().showID              # Bool denoting whether or not to show technique IDs
    Layout().showName            # Bool denoting whether or not to show technique names
    Layout().showAggregateScores # Bool denoting whether or not to utilize Aggregate scores
    Layout().countUnscored       # Bool denoting whether ot not to count unscored techniques as 0s for Aggregates
    Layout().aggregateFunction   # A enum integer denoting which aggregate function to utilize
                                 # 1 - Average, 2 - min, 3 - max, 4 - sum
    Layout().expandedSubtechniques # String denoting how to display sub-techniques in the layer
                                 # "all" - expand all sub-techniques, "annotated" - expand only annotated sub-techniques, "none" - collapse all sub-techniques
    Layout().get_dict()          # Export Layout data as a dictionary object
    Layout().compute_aggregate() # Compute the aggregate score for a technique and it's subtechniques
```
#### Technique Object
```python
    Technique().techniqueID       # String denoting the technique's ID
    Technique().tactic            # String denoting the technique's tactic 
    Technique().comment           # String denoting any comments
    Technique().enabled           # Bool denoting if the technique is enabled
    Technique().score             # Integer denoting technique score
    Technique().aggregateScore    # Integer denoting pre-configured aggregate score
    Technique().color             # String denoting manually configured color code
    Technique().metadata          # List of links to metadata objects
    Technique().showSubtechniques # Bool denoting whether or not to show subtechniques
    Technique().get_dict()        # Export Technique data as a dictionary object
```
#### Gradient Object
```python
    Gradient().colors          # Array of colors (string codes) over which the gradient is to be calculated
    Gradient().minValue        # Integer denoting minimum viable value on the gradient
    Gradient().maxValue        # Integer denoting maximum viable value on the gradient
    Gradient().compute_color() # Calculate the appropriate color for a given score on the gradient
    Gradient().get_dict()      # Export Gradient data as a dictionary object
```
#### LegendItem Object
```python
    LegendItem().label      # String denoting the label for this Legend Item' item
    LegendItem().color      # String denoting the color code for the Legend Item
    LegendItem().get_dict() # Export Legend Item data as a dictionary object
```
#### Metadata/Metadiv Object
```python
    Metadata().name       # String denoting metadata keypair name
    Metadata().value      # String denoting metadata keypair value
    Metadata().get_dict() # Export metadata data as a dictionary object
``` 
```python
    Metadiv().name       # Always set to "DIVIDER"
    Metadiv().value      # Bool denoting active or not
    Metadiv().get_dict() # Export metadiv as a dictionary object
```
A `Metadiv` object is simply a modified version of a `Metadata` object used as a visual divider.