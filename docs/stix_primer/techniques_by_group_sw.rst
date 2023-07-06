Getting techniques used by a group's software
===============

Because a group uses software, and software uses techniques, groups can be considered indirect users of techniques used by their software.
These techniques are oftentimes distinct from the techniques used directly by a group, although there are occasionally intersections in these two sets of techniques.

The following recipe can be used to retrieve the techniques used by a group's software:

.. code-block:: python
    
    from stix2.utils import get_type_from_id
    from stix2 import Filter

    def get_techniques_by_group_software(thesrc, group_stix_id):
        # get the malware, tools that the group uses
        group_uses = [
            r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        # get the technique stix ids that the malware, tools use
        software_uses = thesrc.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses])
        ])

        #get the techniques themselves
        return thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [r.target_ref for r in software_uses])
        ])

    get_techniques_by_group_software(src, "intrusion-set--f047ee18-7985-4946-8bfb-4ed754d3a0dd")
