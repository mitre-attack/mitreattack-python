from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    subtechniques = mitre_attack_data.get_subtechniques(remove_revoked_deprecated=True)

    print(f"Retrieved {len(subtechniques)} ATT&CK sub-techniques.")


if __name__ == "__main__":
    main()
