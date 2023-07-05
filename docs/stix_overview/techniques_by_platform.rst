Techniques by platform
===============


**Techniques by platform**

Techniques are associated with one or more platforms. You can query the techniques
under a specific platform with the following code:

.. code-block:: python
    
    from stix2 import Filter

    def get_techniques_by_platform(thesrc, platform):
        return thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_platforms', '=', platform)
        ])

    # get techniques in the windows platform
    get_techniques_by_platform(src, 'Windows')

