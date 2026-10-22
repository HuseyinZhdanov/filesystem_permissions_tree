# filesystem_permissions_tree

Walks a directory tree and reports every file and directory whose permission bits deviate from an expected mask, producing a violation list for audit or CI.

In practice, checked-in trees on multi-developer systems frequently carry a stray group-write bit (`0o664` on files, `0o775` on directories) from a permissive umask. An exact-mask audit flags these so they can be corrected before a release.

```python
from filesystem_permissions_tree import audit_tree

result = audit_tree(
    ".",
    expected_file_mask=0o664,
    expected_dir_mask=0o775,
)

if not result.is_clean:
    for v in result.violations:
        print(v)
    raise SystemExit(1)
```

`audit_tree(root, expected_file_mask, expected_dir_mask)` returns an `AuditResult` with a `violations` list of `Violation(path, kind, actual_mode, expected_mode)` entries, ordered shallowest-path-first. `AuditResult.is_clean` is `True` when there are no violations; `bool(result)` is also `True` when clean, so `if audit_tree(...):` reads as "the tree passed".

## Why this exists

CI for a checked-in tree (config directories, web roots, `/etc` snapshots) often needs to enforce exact permission bits: world-writable files and setuid binaries should not appear by accident. Generic `find`-based checks are easy to get wrong in shell. This library gives you a single Python call that returns a structured, comparable violation list.

The trade-off: the expected mask is an **exact** mode, not a bitmask of allowed bits. A path violates the policy when `stat(path).st_mode & 0o7777 != expected_mask`. If you need "these bits must be clear, the rest don't matter," that is a different policy and this library will not pretend to support it.

## Edge cases you will hit

- **Symlinks are skipped.** Their own mode is historically `0o777` and carries no real permission information, so reporting them would be noise. Symlink targets are never traversed, which keeps the walk bounded to the tree under `root`.
- **The root directory is checked.** A violation on the root is reported with path `"."`.
- **Unreadable subdirectories raise `PermissionError`** rather than being silently skipped. Silently skipping would hide exactly the anomaly an audit is meant to surface.
- **Paths in violations use forward slashes** regardless of platform, so CI logs are comparable across operating systems.
- **The full `0o7777` range is considered**, including setuid, setgid, and sticky bits. A file with an unexpected setuid bit is a violation even if its lower nine bits match.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

