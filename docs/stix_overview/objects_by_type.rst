Objects by type
===============

**Objects by type**

See [The ATT&CK data model](#The-ATTCK-Data-Model) for mappings of ATT&CK type to STIX type.

.. code-block:: python
    
    from stix2 import Filter

    # use the appropriate STIX type in the query according to the desired ATT&CK type
    groups = src.query([ Filter("type", "=", "intrusion-set") ])
