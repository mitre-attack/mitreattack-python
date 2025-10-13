import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "ics-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    techniques_targeting_assets = mitre_attack_data.get_all_techniques_targeting_all_assets()

    print(f"Techniques targeting assets ({len(techniques_targeting_assets.keys())} assets):")
    for id, techniques in techniques_targeting_assets.items():
        print(f"* {id} - targeted by {len(techniques)} {'technique' if len(techniques) == 1 else 'techniques'}")


if __name__ == "__main__":
    main()
