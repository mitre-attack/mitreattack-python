from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    T1134 = mitre_attack_data.get_object_by_attack_id('T1134', 'attack-pattern')
    print(T1134.serialize(pretty=True))

if __name__ == "__main__":
    main()
