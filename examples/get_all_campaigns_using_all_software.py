from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all campaigns related to software
    campaigns_using_software = mitre_attack_data.get_all_campaigns_using_all_software()

    print(f"Campaigns using software ({len(campaigns_using_software.keys())} software):")
    for id, campaigns in campaigns_using_software.items():
        print(f"* {id} - used by {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")


if __name__ == "__main__":
    main()
