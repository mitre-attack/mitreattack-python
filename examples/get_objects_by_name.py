import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    techniques = mitre_attack_data.get_objects_by_name("System Information Discovery", "attack-pattern")

    for technique in techniques:
        print(technique.serialize(pretty=True))


if __name__ == "__main__":
    main()
