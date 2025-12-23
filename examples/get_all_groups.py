import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)

    print(f"Retrieved {len(groups)} ATT&CK groups.")


if __name__ == "__main__":
    main()
