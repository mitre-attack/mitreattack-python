import pytest

from mitreattack.constants import PLATFORMS_LOOKUP
from mitreattack.stix20 import MitreAttackData


class TestMitreAttackData:
    ###################################
    # STIX Objects Section
    ###################################
    def test_matrices(self, mitre_attack_data_enterprise: MitreAttackData):
        matrices = mitre_attack_data_enterprise.get_matrices()
        assert matrices

    def test_tactics(self, mitre_attack_data_enterprise: MitreAttackData):
        tactics = mitre_attack_data_enterprise.get_tactics()
        assert tactics

    def test_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_techniques(include_subtechniques=False)
        assert techniques

        techniques_with_subs = mitre_attack_data_enterprise.get_techniques(include_subtechniques=True)
        assert techniques_with_subs

    def test_subtechniques(self, mitre_attack_data_enterprise: MitreAttackData):
        subtechniques = mitre_attack_data_enterprise.get_subtechniques()
        assert subtechniques

    def test_mitigations(self, mitre_attack_data_enterprise: MitreAttackData):
        mitigations = mitre_attack_data_enterprise.get_mitigations()
        assert mitigations

    def test_groups(self, mitre_attack_data_enterprise: MitreAttackData):
        groups = mitre_attack_data_enterprise.get_groups()
        assert groups

    def test_software(self, mitre_attack_data_enterprise: MitreAttackData):
        software = mitre_attack_data_enterprise.get_software()
        assert software

    def test_campaigns(self, mitre_attack_data_enterprise: MitreAttackData):
        campaigns = mitre_attack_data_enterprise.get_campaigns()
        assert campaigns

    # Using mitre_attack_data_ics since ICS is the only domain with Assets as of ATT&CK v14
    # def test_assets(self, mitre_attack_data_ics: MitreAttackData):
    #     assets = mitre_attack_data_ics.get_assets()
    #     assert assets

    def test_datasources(self, mitre_attack_data_enterprise: MitreAttackData):
        datasources = mitre_attack_data_enterprise.get_datasources()
        assert datasources

    def test_datacomponents(self, mitre_attack_data_enterprise: MitreAttackData):
        datacomponents = mitre_attack_data_enterprise.get_datacomponents()
        assert datacomponents

    ###################################
    # Get STIX Objects by Value
    # TODO: Finish this section
    ###################################
    @pytest.mark.skip(reason="We need to find a better way to test when platforms change names.")
    def test_techniques_by_platform(self, mitre_attack_data_enterprise: MitreAttackData):
        for platform in PLATFORMS_LOOKUP["enterprise-attack"]:
            if platform == "Cloud":
                # Cloud is a special platform that doesn't have techniques directly
                continue
            techniques = mitre_attack_data_enterprise.get_techniques_by_platform(platform=platform)
            assert techniques

    def test_techniques_by_tactic(self, mitre_attack_data_enterprise: MitreAttackData):
        # TODO: use all tactic shortnames
        tactic_shortnames = ["defense-evasion", "impact"]
        for tactic_shortname in tactic_shortnames:
            techniques = mitre_attack_data_enterprise.get_techniques_by_tactic(
                tactic_shortname=tactic_shortname, domain="enterprise-attack"
            )
            assert techniques

    def test_tactics_by_matrix(self, mitre_attack_data_enterprise: MitreAttackData):
        tactics = mitre_attack_data_enterprise.get_tactics_by_matrix()
        assert tactics

    def test_tactics_by_technique(self, mitre_attack_data_enterprise: MitreAttackData):
        # T1552.001 Credentials In Files
        # Should be in Tactic: credential-access
        tactics = mitre_attack_data_enterprise.get_tactics_by_technique(
            stix_id="attack-pattern--837f9164-50af-4ac0-8219-379d8a74cefc"
        )
        assert tactics

    ###################################
    # Get STIX Object by Value
    # TODO: Finish this section
    ###################################
    def test_groups_by_alias(self, mitre_attack_data_enterprise: MitreAttackData):
        # TODO: assert that Dynamite Panda is an alias of APT18
        alias = "Dynamite Panda"
        groups = mitre_attack_data_enterprise.get_groups_by_alias(alias=alias)
        assert groups

    ###################################
    # Get Object Information
    # TODO: Finish this section
    ###################################
    def test_attack_id(self, mitre_attack_data_enterprise: MitreAttackData):
        group_policy_discovery_stix_id = "attack-pattern--1b20efbf-8063-4fc3-a07d-b575318a301b"
        group_policy_discovery_attack_id = mitre_attack_data_enterprise.get_attack_id(
            stix_id=group_policy_discovery_stix_id
        )
        assert group_policy_discovery_attack_id == "T1615"

    ###################################
    # Unorgainzed test section, but easy to write
    # TODO: Organize this section until nothing is unorganized!
    ###################################
    def test_all_campaigns_attributed_to_all_groups(self, mitre_attack_data_enterprise: MitreAttackData):
        campaigns = mitre_attack_data_enterprise.get_all_campaigns_attributed_to_all_groups()
        assert campaigns

    def test_all_campaigns_using_all_software(self, mitre_attack_data_enterprise: MitreAttackData):
        campaigns = mitre_attack_data_enterprise.get_all_campaigns_using_all_software()
        assert campaigns

    def test_all_campaigns_using_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        campaigns = mitre_attack_data_enterprise.get_all_campaigns_using_all_techniques()
        assert campaigns

    def test_all_datacomponents_detecting_all_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        datacomponents = mitre_attack_data_enterprise.get_all_datacomponents_detecting_all_techniques()
        assert datacomponents

    def test_all_groups_attributing_to_all_campaigns(self, mitre_attack_data_enterprise: MitreAttackData):
        groups = mitre_attack_data_enterprise.get_all_groups_attributing_to_all_campaigns()
        assert groups

    def test_all_groups_using_all_software(self, mitre_attack_data_enterprise: MitreAttackData):
        groups = mitre_attack_data_enterprise.get_all_groups_using_all_software()
        assert groups

    def test_all_groups_using_all_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        groups = mitre_attack_data_enterprise.get_all_groups_using_all_techniques()
        assert groups

    def test_all_mitigations_mitigating_all_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        mitigations = mitre_attack_data_enterprise.get_all_mitigations_mitigating_all_techniques()
        assert mitigations

    def test_all_parent_techniques_of_all_subtechniques(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_all_parent_techniques_of_all_subtechniques()
        assert techniques

    def test_all_software_used_by_all_campaigns(self, mitre_attack_data_enterprise: MitreAttackData):
        software = mitre_attack_data_enterprise.get_all_software_used_by_all_campaigns()
        assert software

    def test_all_software_used_by_all_groups(self, mitre_attack_data_enterprise: MitreAttackData):
        software = mitre_attack_data_enterprise.get_all_software_used_by_all_groups()
        assert software

    def test_all_software_using_all_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        software = mitre_attack_data_enterprise.get_all_software_using_all_techniques()
        assert software

    def test_all_subtechniques_of_all_techniques(self, mitre_attack_data_enterprise: MitreAttackData):
        subtechniques = mitre_attack_data_enterprise.get_all_subtechniques_of_all_techniques()
        assert subtechniques

    def test_all_techniques_detected_by_all_datacomponents(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_all_techniques_detected_by_all_datacomponents()
        assert techniques

    def test_all_techniques_mitigated_by_all_mitigations(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_all_techniques_mitigated_by_all_mitigations()
        assert techniques

    def test_all_techniques_used_by_all_campaigns(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_all_techniques_used_by_all_campaigns()
        assert techniques

    def test_all_techniques_used_by_all_groups(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_all_techniques_used_by_all_groups()
        assert techniques

    def test_all_techniques_used_by_all_software(self, mitre_attack_data_enterprise: MitreAttackData):
        techniques = mitre_attack_data_enterprise.get_all_techniques_used_by_all_software()
        assert techniques
