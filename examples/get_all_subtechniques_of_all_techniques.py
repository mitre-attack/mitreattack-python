import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get subtechniques of techniques
    subtechniques = mitre_attack_data.get_all_subtechniques_of_all_techniques()

    print(f"Sub-techniques of techniques ({len(subtechniques.keys())} parent techniques):")
    for id, subs in subtechniques.items():
        print(f"* {id} has {len(subs)} {'sub-technique' if len(subs) == 1 else 'sub-techniques'}")


if __name__ == "__main__":
    main()
