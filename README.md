# viv-utils
Utilities for working with vivisect

```
pip install viv-utils
```

## Security: `.viv` files and `ALLOW_INSECURE_PICKLE`

vivisect's `.viv` workspace format is serialized with Python's `pickle`,
so loading a `.viv` file can execute arbitrary code. Only load `.viv` files you trust.

`viv_utils.getWorkspace(path)` behaves as follows:

- if `path` ends with `.viv`, it is loaded as a workspace. You asked for it explicitly, so make sure it's trusted.
- otherwise, `path` is always parsed as a program (PE, ELF, etc.), even if its contents look like a workspace.
  Files that look like serialized workspaces are rejected with `UnsupportedFormatError`.
- a cached workspace next to the input (`<path>.viv`) is **ignored by default** and the input is analyzed from scratch.
  If `should_save=True` (the default), `<path>.viv` is then overwritten with the new results.

To reuse cached `<path>.viv` files, opt in by setting the environment variable:

```
ALLOW_INSECURE_PICKLE=1
```

(`1`, `true`, `yes`, and `on` are accepted.) Only do this when you trust every `.viv` file
that may sit next to your inputs: anyone who can write `<path>.viv`, for example inside an
extracted archive or a shared upload directory, can run code in your process.

`viv_utils.getWorkspaceFromFile` never loads workspaces, and
`viv_utils.getWorkspaceFromBytes` / `loadWorkspaceFromBytes` always unpickle their input,
so pass them trusted data only.
