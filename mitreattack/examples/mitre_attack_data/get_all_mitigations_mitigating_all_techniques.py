from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all mitigations related to techniques
    mitigations_mitigating = mitre_attack_data.get_all_mitigations_mitigating_all_techniques()
    
    print(f"Mitigations mitigating techniques ({len(mitigations_mitigating.keys())} techniques):")
    for id, mitigations in mitigations_mitigating.items():
        print(f"* {id} - mitigated by {len(mitigations)} {'mitigation' if len(mitigations) == 1 else 'mitigation'}")


if __name__ == "__main__":
    main()
