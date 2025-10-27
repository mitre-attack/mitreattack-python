import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all software related to techniques
    software_using_techniques = mitre_attack_data.get_all_software_using_all_techniques()

    print(f"Software using techniques ({len(software_using_techniques.keys())} techniques):")
    for id, software in software_using_techniques.items():
        print(f"* {id} - used by {len(software)} software")


if __name__ == "__main__":
    main()
