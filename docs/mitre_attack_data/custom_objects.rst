Custom Objects
==============================================

MITRE ATT&CK implements the following custom STIX objects, which are defined using the 
`stix2 @CustomObject`_ decorator:

.. autoclass:: mitreattack.stix20.Matrix

.. autoclass:: mitreattack.stix20.Tactic

.. autoclass:: mitreattack.stix20.DataSource

.. autoclass:: mitreattack.stix20.DataComponent

The return type of the MitreAttackData methods are determined by the StixObjectFactory method, 
which converts STIX 2 content into a stix2 Custom Object or returns a `STIX 2.0 Domain Object`_.

.. automethod:: mitreattack.stix20.StixObjectFactory

This allows users to work with custom MITRE ATT&CK objects by
parsing and accessing an object's attributes in the same way as
a stix2 Domain Object. 

.. code-block:: python
    :emphasize-lines: 8, 12

    from mitreattack.stix20 import MitreAttackData

    # build the source data
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # retrieve group G0019 by STIX ID (stix2 domain object)
    group = mitre_attack_data.get_object_by_stix_id("intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050") # G0019
    print(group.aliases) # ['Naikon']

    # retrieve tactic TA0001 (stix2 custom object)
    tactic = mitre_attack_data.get_object_by_attack_id("TA0001")
    print(tactic.name) # 'Initial Access'

.. _stix2 @CustomObject: https://stix2.readthedocs.io/en/latest/api/v21/stix2.v21.sdo.html#stix2.v21.sdo.CustomObject
.. _STIX 2.0 Domain Object: https://stix2.readthedocs.io/en/latest/api/v20/stix2.v20.sdo.html#module-stix2.v20.sdo