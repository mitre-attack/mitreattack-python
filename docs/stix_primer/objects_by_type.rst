Objects by type
===============

See `The ATT&CK data model <https://github.com/mitre/cti/blob/master/USAGE.md#The-ATTCK-Data-Model>`_ for mappings of ATT&CK type to STIX type.

.. code-block:: python
    
    from stix2 import Filter

    # use the appropriate STIX type in the query according to the desired ATT&CK type
    groups = src.query([ Filter("type", "=", "intrusion-set") ])
