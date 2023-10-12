from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    software = mitre_attack_data.get_software_by_alias("ShellTea")

    for s in software:
        print(f"{s.name} ({mitre_attack_data.get_attack_id(s.id)})")


if __name__ == "__main__":
    main()
