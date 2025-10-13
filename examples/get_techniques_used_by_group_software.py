import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # Get techniques used by G0087's software
    group_stix_id = "intrusion-set--44e43fad-ffcb-4210-abcf-eaaed9735f80"
    techniques = mitre_attack_data.get_techniques_used_by_group_software(group_stix_id)

    print(f"There are {len(techniques)} techniques used by APT39's software.")


if __name__ == "__main__":
    main()
