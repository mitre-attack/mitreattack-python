import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    techniques = mitre_attack_data.get_techniques_by_platform("Windows", remove_revoked_deprecated=True)

    print(f"There are {len(techniques)} techniques in the Windows platform.")


if __name__ == "__main__":
    main()
