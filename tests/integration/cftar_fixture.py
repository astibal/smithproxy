"""Publish a changed test configuration while preserving native archive resources."""
import pathlib
import subprocess
import tarfile
import tempfile


def publish_config(binary, config):
    archive = config.with_suffix('.cftar')
    tool = pathlib.Path(binary).with_name('smithproxy-cftar')
    # Repack through the public tool so the native archive is validated. Read
    # members individually; never extract archive-supplied paths to disk.
    with tempfile.TemporaryDirectory(dir=config.parent) as temporary:
        directory = pathlib.Path(temporary)
        output = directory / 'updated.cftar'
        command = [str(tool), 'create', '--config', str(config), '--output', str(output)]
        with tarfile.open(archive) as current:
            for index, member in enumerate(current.getmembers()):
                if not member.isfile():
                    continue
                name = member.name.removeprefix('./')
                if name != 'smithproxy.startup.cfg' and not name.startswith(('pki/', 'templates/', 'commands/')):
                    continue
                payload = directory / str(index)
                payload.write_bytes(current.extractfile(member).read())
                if name == 'smithproxy.startup.cfg':
                    command += ['--startup', str(payload)]
                else:
                    command += ['--executable' if member.mode & 0o111 else '--file',
                                f'{name}={payload}']
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        output.replace(archive)
