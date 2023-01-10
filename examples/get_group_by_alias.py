from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    G0016 = mitre_attack_data.get_group_by_alias("Cozy Bear")

    print(G0016.serialize(pretty=True))


if __name__ == "__main__":
    main()
