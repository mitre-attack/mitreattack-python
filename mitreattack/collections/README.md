# collections

This folder contains modules and scripts for working with ATT&CK collections. Collections are sets of ATT&CK STIX objects, grouped for user convienence. For more information about ATT&CK collections, see the corresponding [ATT&CK documentation](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections).

##### Collections Scripts
| script | description |
|:-------|:------------|
|[index_to_markdown](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/collections/index_to_markdown.py)| Provides a means by which to convert a [collection index](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes) into a human-readable markdown file. More information can be found in the corresponding [section](#index_to_markdown.py) below.|

## index_to_markdown.py
index_to_markdown.py provides the IndexToMarkdown class, which provides a way to transform an existing [collection index file](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes) 
into a markdown file for easy of use and reference. The CollectionToMarkdown class is very simple, and provides a 
single method, `index_to_markdown`, which in turn only requires a single parameter - a dictionary representation of the 
desired index file to convert to markdown. An example of how to use the class, and method, can be found below.

#### Example Usage
```python
import json
from mitreattack.collections import IndexToMarkdown

with open('collection_index.json', 'r') as input_file:
    with open('collection_index.md', 'w') as output_file:
        input_index = json.load(input_file)
        generated_md = IndexToMarkdown.index_to_markdown(input_index)  # Convert index to markdown
        output_file.write(generated_md)
print(generated_md)
```