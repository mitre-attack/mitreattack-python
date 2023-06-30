By Alias
===============
#### By alias

The following methodology can be used to find the group corresponding to a given alias:

```python
from stix2 import Filter

def get_group_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])[0]
    
get_group_by_alias(src, 'Cozy Bear')
```