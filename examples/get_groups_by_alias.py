import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    groups = mitre_attack_data.get_groups_by_alias("Cozy Bear")

    for group in groups:
        print(f"{group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
