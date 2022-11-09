from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    S0196 = mitre_attack_data.get_software_by_alias('ShellTea')
    
    print(S0196.serialize(pretty=True))

if __name__ == "__main__":
    main()
