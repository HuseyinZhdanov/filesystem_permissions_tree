import os
import stat
import tempfile
import unittest

from filesystem_permissions_tree import Violation, AuditResult, audit_tree


class _TempTree:
    """Context manager that builds a throwaway directory tree and cleans up."""

    def __init__(self):
        self.root = None
        self._cm = None

    def __enter__(self):
        self._cm = tempfile.TemporaryDirectory()
        self.root = self._cm.__enter__()
        return self.root

    def __exit__(self, *exc):
        if self._cm is not None:
            self._cm.__exit__(*exc)
        return False


def _make(path, kind, mode):
    """Create a file or directory at *path* (relative to cwd) with *mode*.

    The mode is applied *after* creation via os.chmod because tempfile and
    mkdir are affected by umask, which would make the observed mode
    non-deterministic across environments.
    """
    if kind == "dir":
        os.makedirs(path, exist_ok=True)
    else:
        # Touch a regular file.
        with open(path, "wb"):
            pass
    os.chmod(path, mode)


class TestAuditTreeClean(unittest.TestCase):
    def test_clean_tree_returns_no_violations(self):
        with _TempTree() as root:
            _make(os.path.join(root, "sub"), "dir", 0o755)
            _make(os.path.join(root, "sub", "a.txt"), "file", 0o644)
            _make(os.path.join(root, "b.txt"), "file", 0o644)

            # Root itself must match the dir mask too.
            os.chmod(root, 0o755)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            self.assertIsInstance(result, AuditResult)
            self.assertTrue(result.is_clean)
            self.assertEqual(result.violations, [])
            self.assertTrue(bool(result))


class TestAuditTreeViolations(unittest.TestCase):
    def test_file_with_wrong_mode_is_reported(self):
        with _TempTree() as root:
            _make(os.path.join(root, "a.txt"), "file", 0o666)
            os.chmod(root, 0o755)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            self.assertFalse(result.is_clean)
            self.assertFalse(bool(result))
            self.assertEqual(len(result.violations), 1)

            v = result.violations[0]
            self.assertIsInstance(v, Violation)
            self.assertEqual(v.path, "a.txt")
            self.assertEqual(v.kind, "file")
            self.assertEqual(v.actual_mode, 0o666)
            self.assertEqual(v.expected_mode, 0o644)

    def test_directory_with_wrong_mode_is_reported(self):
        with _TempTree() as root:
            _make(os.path.join(root, "sub"), "dir", 0o700)
            os.chmod(root, 0o755)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            self.assertEqual(len(result.violations), 1)
            v = result.violations[0]
            self.assertEqual(v.path, "sub")
            self.assertEqual(v.kind, "directory")
            self.assertEqual(v.actual_mode, 0o700)
            self.assertEqual(v.expected_mode, 0o755)

    def test_root_with_wrong_mode_is_reported(self):
        with _TempTree() as root:
            os.chmod(root, 0o700)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            self.assertEqual(len(result.violations), 1)
            v = result.violations[0]
            self.assertEqual(v.path, ".")
            self.assertEqual(v.kind, "directory")
            self.assertEqual(v.actual_mode, 0o700)

    def test_multiple_violations_are_collected(self):
        with _TempTree() as root:
            _make(os.path.join(root, "good_dir"), "dir", 0o755)
            _make(os.path.join(root, "good_dir", "good.txt"), "file", 0o644)
            _make(os.path.join(root, "good_dir", "bad.txt"), "file", 0o600)
            _make(os.path.join(root, "bad_dir"), "dir", 0o777)
            _make(os.path.join(root, "bad_dir", "inner.txt"), "file", 0o644)
            _make(os.path.join(root, "top_bad.txt"), "file", 0o666)
            os.chmod(root, 0o755)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            paths = [v.path for v in result.violations]
            # Shallowest-first ordering: root-level entries before nested ones.
            self.assertEqual(paths, ["bad_dir", "top_bad.txt", "good_dir/bad.txt"])

    def test_setuid_and_sticky_bits_are_considered(self):
        # 0o4755 = setuid + 0o755.  If the policy says 0o755, the setuid bit is
        # a violation.  This confirms the full 0o7777 range is checked, not just
        # the lower 9 rwx bits.
        with _TempTree() as root:
            _make(os.path.join(root, "suid_file"), "file", 0o4644)
            os.chmod(root, 0o755)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            self.assertEqual(len(result.violations), 1)
            self.assertEqual(result.violations[0].actual_mode, 0o4644)

    def test_violation_str_is_human_readable(self):
        v = Violation(path="a.txt", kind="file", actual_mode=0o666, expected_mode=0o644)
        s = str(v)
        self.assertIn("a.txt", s)
        self.assertIn("0o666", s)
        self.assertIn("0o644", s)


class TestAuditTreeSymlinks(unittest.TestCase):
    def test_symlink_is_not_reported(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks not supported on this platform")
        with _TempTree() as root:
            _make(os.path.join(root, "target.txt"), "file", 0o644)
            os.symlink(
                os.path.join(root, "target.txt"),
                os.path.join(root, "link.txt"),
            )
            os.chmod(root, 0o755)

            result = audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)

            # Only "target.txt" exists as a real file; the symlink must be
            # skipped entirely, not flagged for its typically-0o777 mode.
            paths = [v.path for v in result.violations]
            self.assertNotIn("link.txt", paths)
            self.assertEqual(paths, [])


class TestAuditTreeErrors(unittest.TestCase):
    def test_nonexistent_root_raises_not_a_directory(self):
        with _TempTree() as root:
            missing = os.path.join(root, "does_not_exist")
            with self.assertRaises(NotADirectoryError):
                audit_tree(missing, 0o644, 0o755)

    def test_file_root_raises_not_a_directory(self):
        with _TempTree() as root:
            f = os.path.join(root, "not_a_dir.txt")
            _make(f, "file", 0o644)
            with self.assertRaises(NotADirectoryError):
                audit_tree(f, 0o644, 0o755)

    def test_unreadable_subdirectory_raises_permission_error(self):
        if os.name == "nt":
            self.skipTest("POSIX permission semantics not enforced on Windows")
        with _TempTree() as root:
            _make(os.path.join(root, "locked"), "dir", 0o000)
            os.chmod(root, 0o755)
            try:
                with self.assertRaises(PermissionError):
                    audit_tree(root, expected_file_mask=0o644, expected_dir_mask=0o755)
            finally:
                # Restore so TemporaryDirectory can clean up.
                os.chmod(os.path.join(root, "locked"), 0o755)


if __name__ == "__main__":
    unittest.main()
