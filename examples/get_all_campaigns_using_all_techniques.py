from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all campaigns related to techniques
    campaigns_using_techniques = mitre_attack_data.get_all_campaigns_using_all_techniques()

    print(f"Campaigns using techniques ({len(campaigns_using_techniques.keys())} techniques):")
    for id, campaigns in campaigns_using_techniques.items():
        print(f"* {id} - used by {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")


if __name__ == "__main__":
    main()
