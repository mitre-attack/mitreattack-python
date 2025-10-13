import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all techniques related to data components
    techniques_detected = mitre_attack_data.get_all_techniques_detected_by_all_datacomponents()

    print(f"Techniques detected by data components ({len(techniques_detected.keys())} data components):")
    for id, techniques in techniques_detected.items():
        print(f"* {id} - detects {len(techniques)} {'technique' if len(techniques) == 1 else 'techniques'}")


if __name__ == "__main__":
    main()
