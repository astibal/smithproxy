# Replacement templates

`tls_replacement.txt` is the active TLS warning template. Smithproxy loads it
at startup and reloads it after a successful configuration reload.

Available complete variants:

- `tls_replacement_branded.txt`
- `tls_replacement_dark.txt`
- `tls_replacement_light.txt`

Select a variant by copying it over the active file, for example:

```sh
cp tls_replacement_light.txt tls_replacement.txt
```

Do not use a symbolic link. Template files are deliberately opened with
`O_NOFOLLOW`, must be regular files, and are limited to this directory and to
1 MiB each. This prevents a writable template or a misplaced deployment link
from exposing arbitrary local files in a replacement response.

Every rendered response is self-contained. CSS and the Smithproxy logo remain
inline; browsers do not need network access to display the warning.
