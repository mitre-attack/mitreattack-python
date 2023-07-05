By STIX ID
===============
#### By STIX ID

The following recipe can be used to retrieve an object according to its STIX ID. This is typically the preferred way to retrieve objects when working with ATT&CK data because STIX IDs are guaranteed to be unique.

.. code-block:: python
    g0075 = src.get("intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142")
