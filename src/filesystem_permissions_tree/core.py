"""Core implementation: walk a tree and collect permission-bit deviations.

Design decisions (stated plainly so the tests and the reader share one model):

1. Expected mask is an *exact* permission value, not a bitmask of allowed bits.
   A path violates the policy when ``stat(path).st_mode & 0o7777 != expected_mask``.
   This is the simplest, least-surprising rule for CI: you state the exact mode
   every entry should have, and anything else is a violation.  A mask-based
   "these bits must be set / these must be clear" policy is a different library.

2. Files and directories can have different expected masks.  In most real trees
   directories need the execute bit and files do not, so a single mask would
   either flag every directory or silently allow every file.  Pass separate
   ``expected_file_mask`` and ``expected_dir_mask`` values.

3. Symlinks are *not* followed and are *not* reported.  ``os.lstat`` is used so
   we inspect the link itself, but a symlink's own mode is historically 0o777 on
   most filesystems and carries no real permission information, so reporting it
   would only add noise.  Symlink *targets* are never traversed, which keeps the
   walk bounded to the tree under ``root``.

4. The walk is breadth-first via ``os.scandir`` recursion.  Depth-first would
   work just as well; BFS is used only because it keeps the violation order
   stable and shallow-first, which makes CI diffs easier to read.

5. Permission bits considered are ``0o7777`` -- the low twelve bits covering
   read/write/execute for user/group/other plus setuid, setgid, and sticky.
   Higher bits (file type) are ignored because they are not permissions.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from typing import List


PERMISSION_MASK = 0o7777


@dataclass(frozen=True)
class Violation:
    """A single path whose permission bits deviate from the expected mask.

    Attributes:
        path:  Filesystem path, relative to the audit root, using forward
               slashes regardless of platform (so CI logs are comparable).
        kind:  Either ``"file"`` or ``"directory"``.
        actual_mode:   The observed ``st_mode & 0o7777`` value, as an int
                       (e.g. ``0o644``).
        expected_mode: The mask the path should have had, as an int.
    """

    path: str
    kind: str
    actual_mode: int
    expected_mode: int

    def __str__(self) -> str:
        return (
            f"{self.kind} {self.path}: "
            f"got {oct(self.actual_mode)}, expected {oct(self.expected_mode)}"
        )


@dataclass
class AuditResult:
    """Outcome of an audit run.

    ``violations`` is ordered shallowest-path-first.  ``is_clean`` is True when
    the list is empty, which is the convenience property CI gates typically
    check.
    """

    violations: List[Violation] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.violations) == 0

    def __bool__(self) -> bool:
        # A result is truthy when it is clean, so ``if audit_tree(...):`` reads
        # as "if the tree passed".  This mirrors how ``re.match`` truthiness
        # works and avoids the common ``if not result`` footgun in CI scripts.
        return self.is_clean


def _relative_path(root: str, entry_path: str) -> str:
    """Return ``entry_path`` relative to ``root``, with forward slashes.

    The root itself is represented as ``"."`` so that a violation on the root
    directory has a stable, non-empty label.
    """
    rel = os.path.relpath(entry_path, root)
    return rel.replace(os.sep, "/")


def _check_entry(
    entry_path: str,
    rel_path: str,
    is_dir: bool,
    expected_file_mask: int,
    expected_dir_mask: int,
) -> Violation | None:
    """Return a Violation if the entry's mode deviates, else None.

    Uses ``os.lstat`` so symlinks are inspected without traversal.  As noted in
    the module docstring, symlinks are skipped by the caller before this is
    reached, so the lstat here is defensive: even if a symlink somehow reaches
    this function, we will not follow it.
    """
    st = os.lstat(entry_path)
    actual = st.st_mode & PERMISSION_MASK
    expected = expected_dir_mask if is_dir else expected_file_mask
    if actual != expected:
        return Violation(
            path=rel_path,
            kind="directory" if is_dir else "file",
            actual_mode=actual,
            expected_mode=expected,
        )
    return None


def audit_tree(
    root: str,
    expected_file_mask: int,
    expected_dir_mask: int,
) -> AuditResult:
    """Walk ``root`` and return every permission-bit deviation as a Violation.

    Args:
        root: Directory to audit.  Must exist and be a directory.
        expected_file_mask: Exact ``st_mode & 0o7777`` every regular file must
                            have.
        expected_dir_mask:  Exact ``st_mode & 0o7777`` every directory must
                            have.

    Returns:
        AuditResult whose ``violations`` list is ordered shallowest-first.

    Raises:
        NotADirectoryError: if ``root`` does not exist or is not a directory.
        PermissionError:    if the walker lacks read/execute permission on a
                            directory it needs to descend into.  This is left
                            to propagate because silently skipping unreadable
                            subtrees would hide exactly the kind of anomaly an
                            audit is meant to surface.
    """
    if not os.path.isdir(root):
        raise NotADirectoryError(f"audit root is not a directory: {root!r}")

    violations: List[Violation] = []

    # Queue of (absolute_path, relative_path, is_dir) tuples.  Seeded with the
    # root so the root's own mode is checked too.
    queue: List[tuple[str, str, bool]] = [(root, ".", True)]

    while queue:
        abs_path, rel_path, is_dir = queue.pop(0)

        v = _check_entry(
            abs_path, rel_path, is_dir, expected_file_mask, expected_dir_mask
        )
        if v is not None:
            violations.append(v)

        if not is_dir:
            continue

        try:
            entries = sorted(os.scandir(abs_path), key=lambda e: e.name)
        except PermissionError:
            # Re-raise with the relative path in the message so CI logs point
            # at the unreadable directory rather than at an opaque traceback.
            raise PermissionError(
                f"cannot read directory {rel_path!r} during audit"
            ) from None

        for entry in entries:
            # ``entry.is_symlink()`` uses lstat internally, so it never follows.
            if entry.is_symlink():
                continue

            child_rel = _relative_path(root, entry.path)
            # ``entry.is_dir(follow_symlinks=False)`` is a single lstat-based
            # call; we avoid the extra stat that ``follow_symlinks=True`` would
            # trigger.
            child_is_dir = entry.is_dir(follow_symlinks=False)
            queue.append((entry.path, child_rel, child_is_dir))

    return AuditResult(violations=violations)
