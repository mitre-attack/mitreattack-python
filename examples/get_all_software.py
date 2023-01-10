from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    software = mitre_attack_data.get_software(remove_revoked_deprecated=True)

    print(f"Retrieved {len(software)} ATT&CK software.")


if __name__ == "__main__":
    main()
