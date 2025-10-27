import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    tactics_map = mitre_attack_data.get_tactics_by_matrix()

    for matrix, tactics in tactics_map.items():
        tactic_names = [t["name"] for t in tactics]
        print(f"Tactics in {matrix}: {tactic_names}")


if __name__ == "__main__":
    main()
