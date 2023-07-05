By ATT&CK ID
===============

#### By ATT&CK ID

The following recipe can be used to retrieve an object according to its ATT&CK ID:

.. code-block:: python
from stix2 import Filter

g0075 = src.query([ Filter("external_references.external_id", "=", "G0075") ])[0]


Note: in prior versions of ATT&CK, mitigations had 1:1 relationships with techniques and shared their technique's ID. Therefore the above method does not work properly for techniques because technique ATTT&CK IDs are not truly unique. By specifying the STIX type you're looking for as `attack-pattern` you can avoid this issue.

.. code-block:: python
from stix2 import Filter

t1134 = src.query([ 
    Filter("external_references.external_id", "=", "T1134"), 
    Filter("type", "=", "attack-pattern")
])[0]

The old 1:1 mitigations causing this issue are deprecated, so you can also filter them out that way — see [Removing revoked and deprecated objects](#Removing-revoked-and-deprecated-objects).
