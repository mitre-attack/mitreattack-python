# Relationships

This folder contains a module for building a lookup table of stixID to related objects and relationships. The argument to each accessor function is a STIX2 MemoryStore to build the relationship mappings from.

## Example Usage
``` python
import mitreattack.attackObjects.relationships as relationships

from stix2 import MemoryStore
from pprint import pprint

src = MemoryStore()
src.load_from_file("path/to/enterprise-attack.json")

group_id_to_software = relationships.software_used_by_groups(src)
pprint(group_id_to_software["intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050"])  # G0019
# [
#     {
#         "object": Malware, # S0061
#         "relationship": Relationship # relationship between G0019 and S0061
#     },
#     {
#         ...
#     }
# ]
```