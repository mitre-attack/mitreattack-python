from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    datasources = mitre_attack_data.get_datasources(remove_revoked_deprecated=True)
    print(f"Retrieved {len(datasources)} ATT&CK data sources.")

if __name__ == "__main__":
    main()
