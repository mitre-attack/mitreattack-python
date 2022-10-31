Examples
==============================================

The following are links to scripts of examples on how to use the
``MitreAttackData`` library. See the examples_ directory for more details.

.. _examples: https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/

Getting An ATT&CK Object
------------------------

* `get_object_by_stix_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_object_by_stix_id.py>`_
* `get_object_by_attack_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_object_by_attack_id.py>`_
* `get_object_by_name.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_object_by_name.py>`_
* `get_group_by_alias.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_group_by_alias.py>`_
* `get_software_by_alias.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_software_by_alias.py>`_
* `get_object_type.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_object_type.py>`_
* `get_attack_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_attack_id.py>`_

Getting ATT&CK Objects by Type
------------------------------

* `get_all_matrices.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_matrices.py>`_
* `get_all_tactics.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_tactics.py>`_
* `get_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_techniques.py>`_
* `get_all_mitigations.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_mitigations.py>`_
* `get_all_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_groups.py>`_
* `get_all_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_software.py>`_
* `get_all_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_campaigns.py>`_
* `get_all_datasources.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_datasources.py>`_
* `get_all_datacomponents.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_all_datacomponents.py>`_

Getting Multiple ATT&CK Objects
-------------------------------

* `get_tactics_by_matrix.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_tactics_by_matrix.py>`_
* `get_techniques_by_tactic.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_techniques_by_tactic.py>`_
* `get_techniques_by_platform.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_techniques_by_platform.py>`_
* `get_objects_by_content.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_objects_by_content.py>`_
* `get_objects_created_after.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_objects_created_after.py>`_

Related Objects
-------------------

Technique:Group Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `get_techniques_used_by_group_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_techniques_used_by_group_software.py>`_

Technique:Campaign Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Technique:Software Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Technique:Mitigation Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Technique:Sub-technique Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Technique:Data Component Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Software:Group Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `get_groups_using_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_groups_using_software.py>`_
* `get_groups_using_software_with_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_groups_using_software_with_id.py>`_
* `get_software_used_by_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_software_used_by_groups.py>`_
* `get_software_used_by_groups_with_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_software_used_by_groups_with_id.py>`_

Software:Campaign Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `get_campaigns_using_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_campaigns_using_software.py>`_
* `get_campaigns_using_software_with_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_campaigns_using_software_with_id.py>`_
* `get_software_used_by_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_software_used_by_campaigns.py>`_
* `get_software_used_by_campaign_with_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_software_used_by_campaign_with_id.py>`_

Campaign:Group Relationships
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `get_groups_attributing_to_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_groups_attributing_to_campaigns.py>`_
* `get_groups_attributing_to_campaigns_with_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_groups_attributing_to_campaigns_with_id.py>`_
* `get_campaigns_attributed_to_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_campaigns_attributed_to_groups.py>`_
* `get_campaigns_attributed_to_groups_with_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/mitre_attack_data/get_campaigns_attributed_to_groups_with_id.py>`_

