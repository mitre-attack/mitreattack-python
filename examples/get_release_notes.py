from mitreattack.stix20 import get_release_notes
from mitreattack.stix20 import MitreAttackData


def main():
    MitreAttackData.print_release_notes("enterprise-attack.json", "mobile-attack.json", "ics-attack.json")
    return


if __name__ == "__main__":
    main()