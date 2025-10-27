import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "ics-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all assets targeted by techniques
    assets_targeted_by_techniques = mitre_attack_data.get_all_assets_targeted_by_all_techniques()

    print(f"Assets targeted by techniques ({len(assets_targeted_by_techniques.keys())} techniques):")
    for id, techniques in assets_targeted_by_techniques.items():
        print(f"* {id} - targets {len(techniques)} asset(s)")


if __name__ == "__main__":
    main()
