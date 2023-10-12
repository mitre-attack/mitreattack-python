from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    techniques = mitre_attack_data.get_objects_by_name("System Information Discovery", "attack-pattern")

    for technique in techniques:
        print(technique.serialize(pretty=True))


if __name__ == "__main__":
    main()
