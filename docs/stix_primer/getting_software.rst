Getting software
===============

Because software are the union of two STIX types (`tool` and `malware`), the process for accessing software is slightly more complicated.

.. code-block:: python
    
    from itertools import chain
    from stix2 import Filter

    def get_software(thesrc):
        return list(chain.from_iterable(
            thesrc.query(f) for f in [
                Filter("type", "=", "tool"), 
                Filter("type", "=", "malware")
            ]
        ))

    get_software(src)
