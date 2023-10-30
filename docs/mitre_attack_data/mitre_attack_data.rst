.. _MitreAttackData ref:

MitreAttackData
==============================================

The ``MitreAttackData`` library is used to read in and work with MITRE ATT&CK STIX 2.0 content.
The latest MITRE ATT&CK data files can be found here:

* `Enterprise ATT&CK`_
* `Mobile ATT&CK`_
* `ATT&CK for ICS`_

.. _Enterprise ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
.. _Mobile ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json
.. _ATT&CK for ICS: https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json

*Note*: this library currently only supports STIX 2.0

Usage
-----

This library provides the ability to query the dataset for objects and their related objects. Additional
examples of retrieving data by STIX ID, ATT&CK ID, type, etc. can be found in the :ref:`Examples ref` section.

**Example: Retrieving a technique by its ATT&CK ID**

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    technique = mitre_attack_data.get_object_by_attack_id('T1134', 'attack-pattern')

**Example: Retrieving all group objects**

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    groups = mitre_attack_data.get_groups()

A large part of working with ATT&CK revolves around parsing relationships between objects. It is
useful to track not only the related object but the relationship itself because a description is
often present to contextualize the nature of the relationship. This library can be used to build
a lookup table of STIX ID to related objects and relationships.

**Example: Retrieving relationships between groups and software**

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    group_id_to_software = mitre_attack_data.get_software_used_by_groups()
    print(group_id_to_software["intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050"])  # G0019
    # [
    #     {
    #         "object": Malware, # S0061
    #         "relationships": Relationship[] # relationships between G0019 and S0061
    #     },
    #     {
    #         ...
    #     }
    # ]

When working with functions to return objects based on a set of characteristics, it is likely that a few objects
may be returned which are no longer maintained by ATT&CK. These are objects marked as deprecated or revoked.
We recommend filtering out revoked and deprecated objects whenever possible since they are no longer maintained
by ATT&CK.

**Example: Removing revoked and deprecated objects**

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    mitigations = mitre_attack_data.get_mitigations(remove_revoked_deprecated=True)


To separately remove revoked and deprecated objects from the results of a method:

.. code-block:: python

    from mitreattack.stix20 import MitreAttackData

    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    mitigations = mitre_attack_data.get_mitigations()
    mitigations = mitre_attack_data.remove_revoked_deprecated(mitigations)


Please refer to the `STIX2 Python API Documentation`_ for more information on how to work with
STIX programmatically. We also recommend reading the `ATT&CK Design and Philosophy Paper`_, which
describes high-level overall approach, intention, and usage of ATT&CK.


API Reference
----------------------------------------------

.. autoclass:: mitreattack.stix20.MitreAttackData

.. _STIX2 Python API Documentation: https://stix2.readthedocs.io/en/latest/
.. _ATT&CK Design and Philosophy Paper: https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf