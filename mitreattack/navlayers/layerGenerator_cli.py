import argparse

try:
    from .generators.overview_generator import OverviewGenerator
    from .generators.usage_generator import UsageGenerator
except ImportError:
    from mitreattack.navlayers.generators.overview_generator import OverviewGenerator
    from mitreattack.navlayers.generators.usage_generator import UsageGenerator


def main():
    parser = argparse.ArgumentParser(description='Generate an ATT&CK Navigator layer')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--overview-type', choices=['group', 'software', 'mitigation'],
                       help='Output a matrix where the target type is summarized across the entire dataset.')
    group.add_argument('--mapped-to', help='Output techniques mapped to the given group, software, or mitigation. '
                                           'Argument can be name, associated group/software, or ATT&CK ID.')
    parser.add_argument('-o', '--output', help='Path to the output layer file', default='generated_layer.json')
    parser.add_argument('--domain', help='Which domain to build off of', choices=['enterprise', 'mobile', 'ics'],
                        default='enterprise')
    parser.add_argument('--source', choices=['taxii', 'local'], default='taxii',
                        help='What source to utilize when building the matrix')
    parser.add_argument('--local', help='Path to the local resource if --source=local', default=None)
    args = parser.parse_args()

    if args.overview_type:
        og = OverviewGenerator(source=args.source, matrix=args.domain, local=args.local)
        generated = og.generate_layer(obj_type=args.overview_type)
        print('Generating Layer File')
        generated.to_file(args.output)
        print(f'Layer file generated as {args.output}.')
    elif args.mapped_to:
        ug = UsageGenerator(source=args.source, matrix=args.domain, local=args.local)
        generated = ug.generate_layer(match=args.mapped_to)
        print('Generating Layer File')
        generated.to_file(args.output)
        print(f'Layer file generated as {args.output}.')


if __name__ == '__main__':
    main()
