Tactics by matrix
===============
#### Tactics by matrix

The tactics are individual objects (`x-mitre-tactic`), and their order in a matrix (`x-mitre-matrix`) is
found within the `tactic_refs` property in a matrix. The order of the tactics in that list matches
the ordering of the tactics in that matrix. The following recipe returns a structured list of tactics within each matrix of the input DataStore.

```python
from stix2 import Filter

def getTacticsByMatrix(thesrc):
    tactics = {}
    matrix = thesrc.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])
    
    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(thesrc.get(tactic_id))
    
    return tactics

# get tactic layout
getTacticsByMatrix(src)
```