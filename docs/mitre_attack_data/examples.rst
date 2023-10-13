.. _Examples ref:

Examples
==============================================

The following are links to scripts of examples on how to use the ``MitreAttackData`` 
library. See the examples_ directory in the repository for more details.

.. _examples: https://github.com/mitre-attack/mitreattack-python/tree/master/examples/

Getting An ATT&CK Object
------------------------

* `get_object_by_stix_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_object_by_stix_id.py>`_
* `get_object_by_attack_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_object_by_attack_id.py>`_
* `get_objects_by_name.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_objects_by_name.py>`_
* `get_groups_by_alias.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_groups_by_alias.py>`_
* `get_software_by_alias.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_software_by_alias.py>`_
* `get_campaigns_by_alias.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_campaigns_by_alias.py>`_
* `get_stix_type.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_stix_type.py>`_
* `get_attack_id.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_attack_id.py>`_
* `get_name.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_name.py>`_

Getting ATT&CK Objects by Type
------------------------------

* `get_all_matrices.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_matrices.py>`_
* `get_all_tactics.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_tactics.py>`_
* `get_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_techniques.py>`_
* `get_all_mitigations.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_mitigations.py>`_
* `get_all_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_groups.py>`_
* `get_all_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_software.py>`_
* `get_all_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_campaigns.py>`_
* `get_all_datasources.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_datasources.py>`_
* `get_all_datacomponents.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_datacomponents.py>`_

Getting Multiple ATT&CK Objects
-------------------------------

* `get_tactics_by_matrix.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_tactics_by_matrix.py>`_
* `get_techniques_by_tactic.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_by_tactic.py>`_
* `get_tactics_by_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_tactics_by_technique.py>`_
* `get_techniques_by_platform.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_by_platform.py>`_
* `get_objects_by_content.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_objects_by_content.py>`_
* `get_objects_created_after.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_objects_created_after.py>`_
* `get_objects_modified_after.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_objects_modified_after.py>`_

Related Objects
-------------------

Technique:Group Relationships

* `get_all_groups_using_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_groups_using_all_techniques.py>`_
* `get_groups_using_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_groups_using_technique.py>`_
* `get_all_techniques_used_by_all_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_techniques_used_by_all_groups.py>`_
* `get_techniques_used_by_group.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_used_by_group.py>`_
* `get_techniques_used_by_group_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_used_by_group_software.py>`_

Technique:Campaign Relationships

* `get_all_techniques_used_by_all_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_techniques_used_by_all_campaigns.py>`_
* `get_techniques_used_by_campaign.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_used_by_campaign.py>`_
* `get_all_campaigns_using_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_campaigns_using_all_techniques.py>`_
* `get_campaigns_using_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_campaigns_using_technique.py>`_

Technique:Software Relationships

* `get_all_techniques_used_by_all_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_techniques_used_by_all_software.py>`_
* `get_techniques_used_by_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_used_by_software.py>`_
* `get_all_software_using_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_software_using_all_techniques.py>`_
* `get_software_using_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_software_using_technique.py>`_

Technique:Mitigation Relationships

* `get_all_techniques_mitigated_by_all_mitigations.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_techniques_mitigated_by_all_mitigations.py>`_
* `get_techniques_mitigated_by_mitigation.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_mitigated_by_mitigation.py>`_
* `get_all_mitigations_mitigating_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_mitigations_mitigating_all_techniques.py>`_
* `get_mitigations_mitigating_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_mitigations_mitigating_technique.py>`_

Technique:Sub-technique Relationships

* `get_all_parent_techniques_of_all_subtechniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_parent_techniques_of_all_subtechniques.py>`_
* `get_parent_technique_of_subtechnique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_parent_technique_of_subtechnique.py>`_
* `get_all_subtechniques_of_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_subtechniques_of_all_techniques.py>`_
* `get_subtechniques_of_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_subtechniques_of_technique.py>`_

Technique:Data Component Relationships

* `get_all_datacomponents_detecting_all_techniques.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_datacomponents_detecting_all_techniques.py>`_
* `get_datacomponents_detecting_technique.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_datacomponents_detecting_technique.py>`_
* `get_all_techniques_detected_by_all_datacomponents.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_techniques_detected_by_all_datacomponents.py>`_
* `get_techniques_detected_by_datacomponent.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_techniques_detected_by_datacomponent.py>`_

Software:Group Relationships

* `get_all_groups_using_all_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_groups_using_all_software.py>`_
* `get_groups_using_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_groups_using_software.py>`_
* `get_all_software_used_by_all_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_software_used_by_all_groups.py>`_
* `get_software_used_by_group.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_software_used_by_group.py>`_

Software:Campaign Relationships

* `get_all_campaigns_using_all_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_campaigns_using_all_software.py>`_
* `get_campaigns_using_software.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_campaigns_using_software.py>`_
* `get_all_software_used_by_all_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_software_used_by_all_campaigns.py>`_
* `get_software_used_by_campaign.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_software_used_by_campaign.py>`_

Campaign:Group Relationships

* `get_all_groups_attributing_to_all_campaigns.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_groups_attributing_to_all_campaigns.py>`_
* `get_groups_attributing_to_campaign.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_groups_attributing_to_campaign.py>`_
* `get_all_campaigns_attributed_to_all_groups.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_all_campaigns_attributed_to_all_groups.py>`_
* `get_campaigns_attributed_to_group.py <https://github.com/mitre-attack/mitreattack-python/tree/master/examples/get_campaigns_attributed_to_group.py>`_
