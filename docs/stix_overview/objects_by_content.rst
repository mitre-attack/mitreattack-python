Objects by content
===============

#### Objects by content

Sometimes it may be useful to query objects by the content of their description:

.. code-block:: python
    
    from stix2 import Filter

    def get_techniques_by_content(thesrc, content):
        techniques = src.query([ Filter('type', '=', 'attack-pattern') ])
        return list(filter(lambda t: content.lower() in t.description.lower(), techniques))

    # Get all techniques where the string LSASS appears in the description
    get_techniques_by_content(src, 'LSASS')
