from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    parent_techniques = mitre_attack_data.get_techniques(include_subtechniques=False, remove_revoked_deprecated=True)

    print(f"Retrieved {len(parent_techniques)} ATT&CK parent techniques.")


if __name__ == "__main__":
    main()
