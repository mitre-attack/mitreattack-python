import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    G0075 = mitre_attack_data.get_object_by_stix_id("intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142")

    print(G0075.serialize(pretty=True))


if __name__ == "__main__":
    main()
