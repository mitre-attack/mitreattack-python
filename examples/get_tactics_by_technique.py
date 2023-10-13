from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    technique_id = "attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475"

    tactics = mitre_attack_data.get_tactics_by_technique(technique_id)
    
    print(f"Retrieved {len(tactics)} tactic(s):")

    for t in tactics:
        print(f"* {t.name}")


if __name__ == "__main__":
    main()
