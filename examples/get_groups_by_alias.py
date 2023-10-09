from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    groups = mitre_attack_data.get_groups_by_alias("Cozy Bear")

    for group in groups:
        print(f"{group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
