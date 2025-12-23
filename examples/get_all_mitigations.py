import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    mitigations = mitre_attack_data.get_mitigations(remove_revoked_deprecated=True)

    print(f"Retrieved {len(mitigations)} ATT&CK mitigations.")


if __name__ == "__main__":
    main()
