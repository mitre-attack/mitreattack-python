import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    software = mitre_attack_data.get_software_by_alias("ShellTea")

    for s in software:
        print(f"{s.name} ({mitre_attack_data.get_attack_id(s.id)})")


if __name__ == "__main__":
    main()
