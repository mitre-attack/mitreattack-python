from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all techniques related to campaigns
    techniques_used_by_campaigns = mitre_attack_data.get_techniques_used_by_campaigns()
    print(f"Techniques used by campaigns ({len(techniques_used_by_campaigns.keys())} campaigns):")
    for id, techniques_used in techniques_used_by_campaigns.items():
        print(f"* {id} - {len(techniques_used)} {'technique' if len(techniques_used) == 1 else 'techniques'} used")

    # get techniques used by C0011
    techniques_used_by_c0011 = techniques_used_by_campaigns['campaign--b4e5a4a9-f3be-4631-ba8f-da6ebb067fac']
    print(f"\nTechniques used by C0011 ({len(techniques_used_by_c0011)}):")
    for t in techniques_used_by_c0011:
        technique = t['object']
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
