from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    groups_attributing = mitre_attack_data.get_groups_attributing_to_campaigns()
    print(f"Groups attributing to campaigns ({len(groups_attributing.keys())}):")
    for id, groups in groups_attributing.items():
        print(f"* {id} - attributed to {len(groups)} {'group' if len(groups) == 1 else 'groups'}")


if __name__ == "__main__":
    main()
