from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    
    print(f"Retrieved {len(groups)} ATT&CK groups.")

if __name__ == "__main__":
    main()
