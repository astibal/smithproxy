#!/usr/bin/env python3
"""Run offline template migration sections against an existing native build."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--section', choices=('all', 'archive', 'schema'), default='all')
    args = parser.parse_args()
    build = args.build.resolve()
    source = Path(__file__).resolve().parents[2]

    sections = {}
    if args.section in ('all', 'archive'):
        sections['archive'] = [[str(build / 'sx_gtests_cfg_tar')],
                               [str(build / 'sx_gtests_cfg_io_faults')]]
    if args.section in ('all', 'schema'):
        sections['schema'] = [
            ['python3', str(source / 'tests/process/cftar_schema_upgrade.py'),
             str(build / 'smithproxy'), '--native-archive',
             str(build / 'defaults/smithproxy.cftar'), '--schema', str(schema)]
            for schema in (1039, 1050, 1051, 1052)
        ]

    for name, commands in sections.items():
        for command in commands:
            subprocess.run(command, check=True, timeout=180)
        print(f'PASS section {name}', flush=True)
    print('PASS suite default-templates', flush=True)


if __name__ == '__main__':
    main()
