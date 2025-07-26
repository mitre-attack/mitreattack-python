Custom Objects
==============================================

**Note**: This section includes nonessential information that is only relevant to users
who want a more advanced understanding of how this library is implemented.

ATT&CK uses a mix of predefined and custom STIX objects to implement ATT&CK concepts. More
information about the mapping of ATT&CK concepts to STIX 2.0 objects can be found in the the
`ATT&CK Data Model documentation`_. The ``MitreAttackData`` library implements the following
`custom STIX object types`_:

.. autoclass:: mitreattack.stix20.Matrix

    **Custom Properties:**

    * **tactic_refs** (*list[str]*) - The matrix array that contains an ordered list of
      ``x-mitre-tactic`` STIX IDs corresponding to the tactics of the matrix. The order of
      ``tactic_refs`` determines the order the tactics should appear within the matrix.


.. autoclass:: mitreattack.stix20.Tactic

    **Custom Properties:**

    * **x_mitre_shortname** (*str*) - The shortname of the tactic that is used for mapping
      techniques to the tactic. This corresponds to the ``kill_chain_phases.phase_name``
      of the techniques in the tactic.

.. autoclass:: mitreattack.stix20.DataSource

    **Custom Properties:**

    * **x_mitre_platforms** (*list[str]*) - The list of platforms that apply to the data source.
    * **x_mitre_collection_layers** (*list[str]*) - The list of places the data can be
      collected from.

.. autoclass:: mitreattack.stix20.DataComponent

    **Custom Properties:**

    * **x_mitre_data_source_ref** (*str*) - The STIX ID of the data source this component
      is a part of.

.. autoclass:: mitreattack.stix20.Asset

    **Custom Properties:**

    * **x_mitre_platforms** (*list[str]*) - The list of platforms that apply to the asset.
    * **x_mitre_related_assets** (*list[dict]*) - The list of related assets.

STIX Object Factory
-------------------

The return type of the ``MitreAttackData`` methods are determined by the StixObjectFactory method,
which converts STIX 2.0 content into a stix2 Custom Object or returns a `STIX 2.0 Domain Object`_.

.. automethod:: mitreattack.stix20.StixObjectFactory

This allows users to work with custom MITRE ATT&CK objects by
parsing and accessing an object's attributes in the same way as
a stix2 Domain Object:

.. code-block:: python
    :emphasize-lines: 8, 12

    from mitreattack.stix20 import MitreAttackData

    # build the source data
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # retrieve group G0019 by STIX ID (stix2 Domain Object)
    group = mitre_attack_data.get_object_by_stix_id("intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050") # G0019
    print(group.aliases) # ['Naikon']

    # retrieve tactic TA0001 (stix2 Custom Object)
    tactic = mitre_attack_data.get_object_by_attack_id("TA0001")
    print(tactic.name) # 'Initial Access'

.. _custom STIX object types: https://stix2.readthedocs.io/en/latest/guide/custom.html#Custom-STIX-Object-Types
.. _STIX 2.0 Domain Object: https://stix2.readthedocs.io/en/latest/api/v20/stix2.v20.sdo.html#module-stix2.v20.sdo
.. _ATT&CK Data Model documentation: https://github.com/mitre/cti/blob/ATT%26CK-v12.0/USAGE.md#the-attck-data-model