from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    mitigations = mitre_attack_data.get_mitigations(remove_revoked_deprecated=True)
    print(f"Retrieved {len(mitigations)} ATT&CK mitigations.")

if __name__ == "__main__":
    main()
