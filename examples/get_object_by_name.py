from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    T1082 = mitre_attack_data.get_objects_by_name("System Information Discovery", "attack-pattern")

    print(T1082[0].serialize(pretty=True))


if __name__ == "__main__":
    main()
