Getting a revoking object
===============

**Getting a revoking object**

When an object is replaced by another object, it is marked with the field `revoked` and a relationship of type `revoked-by` is created where the `source_ref` is the revoked object and the `target_ref` is the revoking object. This relationship can be followed to find the replacing object:

.. code-block:: python
    
    from stix2 import Filter

    def getRevokedBy(stix_id, thesrc):
        relations = thesrc.relationships(stix_id, 'revoked-by', source_only=True)
        revoked_by = thesrc.query([
            Filter('id', 'in', [r.target_ref for r in relations]),
            Filter('revoked', '=', False)
        ])
        if revoked_by is not None:
            revoked_by = revoked_by[0]

        return revoked_by

    getRevokedBy("attack-pattern--c16e5409-ee53-4d79-afdc-4099dc9292df", src)
