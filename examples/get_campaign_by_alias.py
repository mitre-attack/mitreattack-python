from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    C0001 = mitre_attack_data.get_campaign_by_alias("Frankenstein")

    print(C0001.serialize(pretty=True))


if __name__ == "__main__":
    main()
