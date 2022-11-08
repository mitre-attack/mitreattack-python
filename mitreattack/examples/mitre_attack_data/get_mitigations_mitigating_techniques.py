from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all mitigations related to techniques
    mitigations_mitigating = mitre_attack_data.get_mitigations_mitigating_techniques()
    print(f"Mitigations mitigating techniques ({len(mitigations_mitigating.keys())} techniques):")
    for id, mitigations in mitigations_mitigating.items():
        print(f"* {id} - mitigated by {len(mitigations)} {'mitigation' if len(mitigations) == 1 else 'mitigation'}")

    # get groups related to T1014
    mitigations_mitigating_t1014 = mitigations_mitigating['attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b']
    print(f"\nMitigations mitigating T1014 ({len(mitigations_mitigating_t1014)}):")
    for m in mitigations_mitigating_t1014:
        mitigation = m['object']
        print(f"* {mitigation.name} ({mitre_attack_data.get_attack_id(mitigation.id)})")


if __name__ == "__main__":
    main()
