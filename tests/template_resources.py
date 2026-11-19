#!/usr/bin/env python3
"""Materialize disposable legacy test fixtures from the sole C++ resource source.

No generated templates are checked into the source tree. The unit and process
suites also validate the compiled payload through the native archive builder.
"""
import argparse
import atexit
from functools import lru_cache
from pathlib import Path
import re
import tempfile


def templates(source):
    text = (Path(source) / 'src/resources/default_templates.cpp').read_text()
    matches = re.findall(r'\{"templates/replacement/en/([^"/]+)", R"sx_template\((.*?)\)sx_template"\}',
                         text, re.S)
    if not matches or len(dict(matches)) != len(matches):
        raise ValueError('invalid embedded template fixture source')
    return {name: content.encode() for name, content in matches}


def write_templates(source, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in templates(source).items():
        (destination / name).write_bytes(content)
    return destination


@lru_cache(maxsize=None)
def template_directory(source):
    temporary = tempfile.TemporaryDirectory(prefix='smithproxy-template-fixture-')
    atexit.register(temporary.cleanup)
    return write_templates(source, temporary.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    write_templates(args.source, args.output)
