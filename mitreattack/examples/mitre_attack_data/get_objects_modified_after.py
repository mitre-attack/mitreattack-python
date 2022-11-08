from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    objects = mitre_attack_data.get_objects_modified_after('2022-10-01T00:00:00.000Z')
    print(f"There were {len(objects)} objects modified after 1 October 2022")


if __name__ == "__main__":
    main()
