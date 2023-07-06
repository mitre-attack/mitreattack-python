By Name
===============


The following recipe retrieves an object according to its name:

.. code-block:: python
    
    from stix2 import Filter

    def get_technique_by_name(thesrc, name):
        filt = [
            Filter('type', '=', 'attack-pattern'),
            Filter('name', '=', name)
        ]
        return thesrc.query(filt)
    # get the technique titled "System Information Discovery"
    get_technique_by_name(src, 'System Information Discovery')
