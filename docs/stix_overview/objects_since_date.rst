Objects created or modified since a given date
===============
#### Objects created or modified since a given date

Sometimes you may want to get a list of objects which have been created or modified after a certain time.

```python
from stix2 import Filter

def get_created_after(thesrc, timestamp):
    filt = [
        Filter('created', '>', timestamp)
    ]
    return thesrc.query(filt)

get_created_after(src, "2018-10-01T00:14:20.652Z")


def get_modified_after(thesrc, timestamp):
    filt = [
        Filter('modified', '>', timestamp)
    ]
    return thesrc.query(filt)
    
get_modified_after(src, "2018-10-01T00:14:20.652Z")
```

We don't recommend you use this method to detect a change to the contents of the knowledge base. For detecting an update to the overall knowledge base we recommend using requests to [check the list of released versions of ATT&CK](https://github.com/mitre/cti/blob/master/USAGE.md#access-a-specific-version-of-attck).
