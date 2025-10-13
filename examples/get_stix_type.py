import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    stix_id = "intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142"
    object_type = mitre_attack_data.get_stix_type(stix_id)

    print(f"This object ({stix_id}) is of type '{object_type}'")


if __name__ == "__main__":
    main()
