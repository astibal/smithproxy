# Offline template upgrades

All shipped replacement-page templates are embedded as raw strings in
`src/resources/default_templates.cpp`, under `sx::resources::default_templates`.
The payload is separate from migration and runtime code. No network access or
installed template directory is required to obtain upgrade defaults.

Legacy-to-CFtar migration preserves existing template files and supplies missing
ones from the embedded set. Unreadable files, symlinks and non-regular files still
fail migration; defaults are not a substitute for an invalid existing file.

Schema 1053 completes the template set in older native archives, including
archives already at schema 1051 or 1052. Existing resources always win, even when
empty. The upgraded configuration and missing resources are saved together through
the existing archive transaction. Check-only mode validates the upgrade in memory
without writing it. A second start does not rewrite the archive.

These are upgrade defaults, not a permanent rendering fallback. Removing a
required template from a current-schema archive remains a validation error.

`src/resources/default_templates.cpp` is the only maintained default payload.
The build invokes `smithproxy-cftar create --default-templates` to seed the
installation archive. Legacy test fixtures are generated temporarily from those
resources; there is no checked-in `etc/msg` template copy.

Run the regression suite in an isolated test environment:

```sh
python3 tests/process/default_templates_suite.py --build /path/to/build
```

`--section archive` runs archive and filesystem fault tests; `--section schema`
runs process upgrades from schemas 1039, 1050, 1051 and 1052.

## Manual maintenance

Privileged exec-mode CLI commands provide the same offline defaults:

```
maintenance template fix-missing
maintenance template rollback
```

`fix-missing` only inserts absent shipped resources. `rollback` asks for
confirmation, then restores all shipped templates to their embedded contents.
User-added template names, configuration, certificates and other resources are
preserved. The commands publish one complete CFtar with the existing recovery
backup mechanism. They refuse unsaved running configuration, an active commit
lease, legacy storage or pending startup changes.

Changed templates require a process restart to activate; the command never
restarts the proxy itself. If nothing changes, no write, backup replacement or
restart is required.

## Export, edit, import

```
maintenance template export /tmp/replacement-edit
# Edit files inside /tmp/replacement-edit/en/
maintenance template import /tmp/replacement-edit
```

Export reads the current CFtar contents, not built-in defaults, and creates a
new private directory. Existing destinations are refused. Import requires exactly
the complete shipped English file set in `en/`, with no additional languages,
files, subdirectories or symlinks. Templates are limited to 1 MiB each. Every
variant is parsed with the renderer, resolving includes only within the imported
set. Parsing validates the template language, not browser HTML semantics.

Only after validation does import publish all changed templates in one archive
transaction, preserving configuration, certificates and unrelated resources.
Missing files are not merged from the existing archive. Changes require restart;
unchanged imports do not rewrite the archive or its recovery backup. Paths are
accessed with the running proxy account's permissions.
