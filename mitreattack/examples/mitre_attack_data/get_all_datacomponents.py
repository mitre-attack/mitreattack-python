from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    datacomponents = mitre_attack_data.get_datacomponents(remove_revoked_deprecated=True)
    print(f"Retrieved {len(datacomponents)} ATT&CK data components.")

if __name__ == "__main__":
    main()
