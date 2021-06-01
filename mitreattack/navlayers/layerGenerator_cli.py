import argparse

try:
    from generators.overview_generator import OverviewGenerator
    from generators.usage_generator import UsageGenerator
except ImportError:
    from mitreattack.navlayers.generators.overview_generator import OverviewGenerator
    from mitreattack.navlayers.generators.usage_generator import UsageGenerator


def main():
    parser = argparse.ArgumentParser(description='Generate an ATT&CK Navigator layer')
    parser.add_argument('-m', '--mode', choices=['overview', 'usage'], required=True,
                        help='Generate a complete overview or the specific usage for a entity')
    parser.add_argument('-t', '--type', choices=['group', 'software', 'mitigation'], required=True,
                        help='What kind of object to build the layer for')
    parser.add_argument('-i', '--identity', help='The identity (id/name) of the desired entity '
                                                 '(required for usage generation)', default=None)
    parser.add_argument('-o', '--output', help='Path to the output layer file', default='generated_layer.json')
    parser.add_argument('--matrix', help='Which matrix to build off of', default='enterprise')
    parser.add_argument('--source', choices=['taxii', 'local'], default='taxii',
                        help='What source to utilize when building the matrix')
    parser.add_argument('--local', help='Path to the local resource if --source=local', default=None)
    args = parser.parse_args()

    if args.mode == 'overview':
        og = OverviewGenerator(source=args.source, matrix=args.matrix, local=args.local)
        generated = og.generate_layer(obj_type=args.type)
        print('Generating Layer File')
        generated.to_file(args.output)
        print(f'Layer file generated as {args.output}.')
    elif args.mode == 'usage':
        if args.identity:
            ug = UsageGenerator(source=args.source, matrix=args.matrix, local=args.local)
            generated = ug.generate_layer(match=args.identity, obj_type=args.typ)
            print('Generating Layer File')
            generated.to_file(args.output)
            print(f'Layer file generated as {args.output}.')
        else:
            print('No identity provided (--identity). Without an identity, no "usage" type layer can be generated. '
                  'Aborting...')


if __name__ == '__main__':
    main()
