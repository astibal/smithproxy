# Vendored ls-qpack

- Project: https://github.com/litespeedtech/ls-qpack
- Version: `v2.7.0`
- Commit: `91567706c41c0d97ab8dc576873ecd472d7869fa`
- Imported: 2026-09-25
- License: MIT (`LICENSE.ls-qpack`)

The bundled xxHash sources come from the same ls-qpack release and are kept
unchanged. They use the BSD 2-Clause license (`LICENSE.xxhash`, also embedded
in both source files).
Smithproxy builds both components into the private static target
`smithproxy_qpack`; no system QPACK or xxHash package is required.

The imported upstream files are:

- `lsqpack.c`
- `lsqpack.h`
- `lsxpack_header.h`
- `huff-tables.h`
- `deps/xxhash/xxhash.c`
- `deps/xxhash/xxhash.h`

The import normalizes one trailing space in `lsqpack.h` and one extra blank
line at the end of `xxhash.c` so Smithproxy's `git diff --check` remains clean;
there are no semantic source changes. Do not modify these files locally. Put
Smithproxy-specific adaptation in the QUIC/H3 wrapper and update this record
when importing a newer upstream tag.
