from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all groups related to campaigns
    groups_attributing = mitre_attack_data.get_all_groups_attributing_to_all_campaigns()
    
    print(f"Groups attributing to campaigns ({len(groups_attributing.keys())} campaigns):")
    for id, groups in groups_attributing.items():
        print(f"* {id} - attributed to {len(groups)} {'group' if len(groups) == 1 else 'groups'}")


if __name__ == "__main__":
    main()
