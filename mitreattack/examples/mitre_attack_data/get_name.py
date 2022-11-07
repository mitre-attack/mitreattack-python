from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    stix_id = "intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142"
    object_name = mitre_attack_data.get_name(stix_id)
    print(f"Name: {object_name}")

if __name__ == "__main__":
    main()
