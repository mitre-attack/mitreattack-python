Removing revoked and deprecated objects
===============

Revoked and deprecated objects are kept in the knowledge base so that workflows relying on those objects are not
broken. We recommend you filter out revoked and deprecated objects from your views whenever possible since they are no
longer maintained by ATT&CK.

We recommend _not_ using built-in STIX filters for removing revoked objects (e.g ``Filter('revoked', '=', False)``). This is because the behavior of this specific filter is inconsistent depending on the method of access (using local data or accessing via the TAXII server). We recommend using the following code example to filter revoked objects instead. See `issue #127 <https://github.com/mitre/cti/issues/127>`_ for more details.

.. code-block:: python
    
    from stix2 import Filter

    def remove_revoked_deprecated(stix_objects):
        """Remove any revoked or deprecated objects from queries made to the data source"""
        # Note we use .get() because the property may not be present in the JSON data. The default is False
        # if the property is not set.
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects
            )
        )

    mitigations = src.query([ Filter("type", "=", "course-of-action") ])
    mitigations = remove_revoked_deprecated(mitigations)
