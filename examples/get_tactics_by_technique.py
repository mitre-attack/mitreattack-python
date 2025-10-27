import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)
    technique_id = "attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475"

    tactics = mitre_attack_data.get_tactics_by_technique(technique_id)

    print(f"Retrieved {len(tactics)} tactic(s):")

    for t in tactics:
        print(f"* {t.name}")


if __name__ == "__main__":
    main()
