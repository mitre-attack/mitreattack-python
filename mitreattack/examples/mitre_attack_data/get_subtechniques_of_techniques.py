from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get subtechniques of techniques
    subtechniques = mitre_attack_data.get_subtechniques_of_techniques()
    print(f"Sub-techniques of techniques ({len(subtechniques.keys())} parent techniques):")
    for id, subs in subtechniques.items():
        print(f"* {id} has {len(subs)} {'sub-technique' if len(subs) == 1 else 'sub-techniques'}")

    # get the subtechniques of T1195
    subs_of_t1195 = subtechniques['attack-pattern--3f18edba-28f4-4bb9-82c3-8aa60dcac5f7']
    print(f"\nSub-techniques of T1195 ({len(subs_of_t1195)}):")
    for s in subs_of_t1195:
        sub = s['object']
        print(f"* {sub.name} ({mitre_attack_data.get_attack_id(sub.id)})")


if __name__ == "__main__":
    main()
