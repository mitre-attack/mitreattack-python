from mitreattack.stix20 import MitreAttackData


def print_procedure_examples(mitre_attack_data, attack_objects_using_technique):
    for attack_object in attack_objects_using_technique:
        stix_object = attack_object["object"]
        attack_id = mitre_attack_data.get_attack_id(stix_id=stix_object["id"])
        name = stix_object["name"]
        procedure_description = attack_object["relationship"].get("description")

        print(f"[{attack_id}] {name}: {procedure_description}")


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

    for tactic in tactics:
        tactic_name = tactic["name"]
        tactic_shortname = tactic["x_mitre_shortname"]

        techniques = mitre_attack_data.get_techniques_by_tactic(
            tactic_shortname, "enterprise-attack", remove_revoked_deprecated=True
        )

        print("\n=====================================================")
        print(f"================= {tactic_name} =================")
        print("=====================================================\n")

        for technique in techniques:
            technique_stix_id = technique["id"]
            groups_using_technique = mitre_attack_data.get_groups_using_technique(technique_stix_id=technique_stix_id)
            software_using_technique = mitre_attack_data.get_software_using_technique(
                technique_stix_id=technique_stix_id
            )
            campaigns_using_technique = mitre_attack_data.get_campaigns_using_technique(
                technique_stix_id=technique_stix_id
            )

            print_procedure_examples(
                mitre_attack_data=mitre_attack_data, attack_objects_using_technique=groups_using_technique
            )
            print_procedure_examples(
                mitre_attack_data=mitre_attack_data, attack_objects_using_technique=software_using_technique
            )
            print_procedure_examples(
                mitre_attack_data=mitre_attack_data, attack_objects_using_technique=campaigns_using_technique
            )


if __name__ == "__main__":
    main()
