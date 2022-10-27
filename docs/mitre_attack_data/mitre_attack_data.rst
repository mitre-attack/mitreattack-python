.. _MitreAttackData ref:

MitreAttackData
==============================================

The ``MitreAttackData`` library is used to read in and work with MITRE ATT&CK STIX 2.0 content.
The latest MITRE ATT&CK STIX 2.0 files can be found here:

* `Enterprise ATT&CK`_
* `Mobile ATT&CK`_
* `ICS ATT&CK`_

.. _Enterprise ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
.. _Mobile ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json
.. _ICS ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json

This library provides the ability to query the dataset for objects and their related objects. When working with 
queries to return objects based on a set of characteristics, it is likely that a few objects will be returned 
which are no longer maintained by ATT&CK. These are objects marked as deprecated or revoked. We recommend filtering 
out revoked and deprecated objects whenever possible since they are no longer maintained by ATT&CK.

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")
    groups = mitre_attack_data.get_groups() 

A large part of working with ATT&CK revolves around parsing relationships between objects. It is 
useful to track not only the related object but the relationship itself because a description is 
often present to contextualize the nature of the relationship. This library can be used to build
a lookup table of STIX ID to related objects and relationships.

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")
    group_id_to_software = mitre_attack_data.get_software_used_by_groups()
    print(group_id_to_software["intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050"])  # G0019
    # [
    #     {
    #         "object": Malware, # S0061
    #         "relationship": Relationship # relationship between G0019 and S0061
    #     },
    #     {
    #         ...
    #     }
    # ]

Please refer to the `STIX2 Python API Documentation`_ for more information on how to work with 
STIX programmatically.

*Note*: this library currently only supports STIX 2.0


API Reference
----------------------------------------------

.. autoclass:: mitreattack.stix20.MitreAttackData

.. _STIX2 Python API Documentation: https://stix2.readthedocs.io/en/latest/