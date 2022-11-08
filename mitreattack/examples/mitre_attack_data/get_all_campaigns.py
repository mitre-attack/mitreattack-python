from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    campaigns = mitre_attack_data.get_campaigns(remove_revoked_deprecated=True)
    print(f"Retrieved {len(campaigns)} ATT&CK campaigns.")

if __name__ == "__main__":
    main()
