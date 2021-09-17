# collections

This folder contains modules and scripts for working with ATT&CK collections. Collections are sets of ATT&CK STIX objects, grouped for user convienence. For more information about ATT&CK collections, see the corresponding [ATT&CK documentation](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections).

##### Collections Scripts
| script | description |
|:-------|:------------|
|[index_to_markdown](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/collections/index_to_markdown.py)| Provides a means by which to convert a [collection index](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes) into a human-readable markdown file. More information can be found in the corresponding [section](#index_to_markdown.py) below.|
|[collection_to_index](https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/collections/index_to_markdown.py)| Provides a means by which to convert a [collection](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections) into a easy-to-share [index file](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes). More information can be found in the corresponding [section](#collection_to_index.py) below.|

## index_to_markdown.py
index_to_markdown.py provides the IndexToMarkdown class, which provides a way to transform an existing [collection index file](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes) 
into a markdown file for easy of use and reference. The IndexToMarkdown class is very simple, and provides a 
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

## collection_to_index.py
collection_to_index.py provides the CollectionToIndex class, which proves a means by which to summarize existing [collections](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections)
into a single [collection index](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes) file.
The CollectionToIndex class contains the generate_index function, which when provided with a name, description, root url (pointing to where the raw collections are stored), 
and a list of either files, folders, or already loaded bundles in the form of dictionaries, will create a summarizing index.
#### Example Usage
```python
import json
from mitreattack.collections import CollectionToIndex

output_indexA = CollectionToIndex.generate_index(name='example', description='example index', 
                                                 root_url='www.example.com', 
                                                 files=['/path/to/collection1.json', '/path/to/collection2.json'], 
                                                 folders=None, bundles=None)
output_indexB = CollectionToIndex.generate_index(name='example2', description='demonstration index',
                                                 root_url='www.example.com',
                                                 files=None, folders=['/path/to/folder/with/collections'], bundles=None)
with open('path/to/bundle/bundleC.json', 'r') as f:
    data = json.load(f)
output_indexC = CollectionToIndex.generate_index(name='example3', description='exhibit index',
                                                 root_url='www.example.com',
                                                 files=None, folders=None, bundles=[data])
for destination in [('A', output_indexA), ('B', output_indexB), ('C', output_indexC)]:
    with open(f'path/to/output/index{destination[0]}.json', 'w') as f:
        json.dump(f, destination[1])
```
