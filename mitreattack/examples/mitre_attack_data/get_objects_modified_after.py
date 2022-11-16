from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    date = '2022-10-01'
    objects = mitre_attack_data.get_objects_modified_after(date)
    
    print(f"There were {len(objects)} objects modified after {date}")


if __name__ == "__main__":
    main()
