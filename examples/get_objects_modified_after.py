import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    date = "2022-10-01"
    objects = mitre_attack_data.get_objects_modified_after(date)

    print(f"There are {len(objects)} objects modified after {date}")


if __name__ == "__main__":
    main()
