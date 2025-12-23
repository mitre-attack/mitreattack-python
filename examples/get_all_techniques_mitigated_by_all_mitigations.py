import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all techniques related to mitigations
    techniques_mitigated = mitre_attack_data.get_all_techniques_mitigated_by_all_mitigations()

    print(f"Techniques mitigated by mitigations ({len(techniques_mitigated.keys())} mitigations):")
    for id, techniques in techniques_mitigated.items():
        print(f"* {id} - mitigates {len(techniques)} {'technique' if len(techniques) == 1 else 'techniques'}")


if __name__ == "__main__":
    main()
