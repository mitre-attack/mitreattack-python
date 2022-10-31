from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    techniques = mitre_attack_data.get_techniques_by_tactic('defense-evasion', 'enterprise-attack', remove_revoked_deprecated=True)
    print(f"There are {len(techniques)} techniques related to the Defense Evasion tactic.")

if __name__ == "__main__":
    main()
