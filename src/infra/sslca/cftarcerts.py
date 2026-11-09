#!/usr/bin/env python3

"""Temporary certificate workspace backed by one atomic CFtar update."""

from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile


ARCHIVE = Path(os.environ.get("SMITHPROXY_CFTAR", "/etc/smithproxy/smithproxy.cftar"))
CFTAR = os.environ.get("SMITHPROXY_CFTAR_CMD", "smithproxy-cftar")
RESOURCE_ROOT = "pki/ca/default"
CERTIFICATE_FILES = (
    "ca-cert.pem",
    "ca-key.pem",
    "srv-cert.pem",
    "srv-key.pem",
    "cl-cert.pem",
    "cl-key.pem",
    "portal-cert.pem",
    "portal-key.pem",
    "portal-gen.info",
    "sslca.json",
)


def _run(arguments, *, output=None, required=True):
    """Run the installed CFtar tool without a shell or interpolated command."""
    result = subprocess.run(
        [CFTAR, *arguments], stdout=output or subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False)
    if required and result.returncode != 0:
        raise RuntimeError("smithproxy-cftar operation failed: " + " ".join(arguments[:2]))
    return result.returncode == 0


def _export(archive, resource, target):
    """Export an optional resource into a private workspace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if not _run(["resource", "export", str(archive), resource, str(target)], required=False):
        target.unlink(missing_ok=True)


class CertificateWorkspace:
    """Present legacy certificate tools with a directory and publish changes once."""

    def __init__(self, requested_root):
        self.requested_root = Path(requested_root)
        self.temporary = None
        self.root = self.requested_root
        self.config_file = self.root / "smithproxy.cfg"
        self._original = {}

    def open(self):
        """Materialize native certificate resources when CFtar is active."""
        if not ARCHIVE.is_file():
            return self

        self.temporary = tempfile.TemporaryDirectory(prefix="smithproxy-certificates-")
        self.root = Path(self.temporary.name)
        self.config_file = self.root / "smithproxy.cfg"
        try:
            with self.config_file.open("wb") as output:
                _run(["get", str(ARCHIVE), "smithproxy.cfg"], output=output)

            directory = self.root / "certs" / "default"
            for name in CERTIFICATE_FILES:
                target = directory / name
                _export(ARCHIVE, f"{RESOURCE_ROOT}/{name}", target)
                self._original[name] = target.read_bytes() if target.is_file() else None
        except Exception:
            self.close()
            raise
        return self

    def publish(self):
        """Publish every changed certificate file as one archive generation."""
        if self.temporary is None:
            return
        directory = self.root / "certs" / "default"
        mappings = []
        for name in CERTIFICATE_FILES:
            target = directory / name
            if target.is_file() and target.read_bytes() != self._original[name]:
                mappings.append(f"{RESOURCE_ROOT}/{name}={target}")
        if mappings:
            _run(["resource", "import-set", str(ARCHIVE), *mappings])

    def close(self):
        """Remove all temporarily materialized private key material."""
        if self.temporary is not None:
            self.temporary.cleanup()
            self.temporary = None


@contextmanager
def certificate_workspace(requested_root="/etc/smithproxy"):
    """Yield a legacy-shaped workspace and atomically publish successful edits."""
    workspace = CertificateWorkspace(requested_root).open()
    try:
        yield workspace
        workspace.publish()
    finally:
        workspace.close()
