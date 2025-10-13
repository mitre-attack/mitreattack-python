import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    T1134 = mitre_attack_data.get_object_by_attack_id("T1134", "attack-pattern")

    mitre_attack_data.print_stix_object(T1134, pretty=True)


if __name__ == "__main__":
    main()
