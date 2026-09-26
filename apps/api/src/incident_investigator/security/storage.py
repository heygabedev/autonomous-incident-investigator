"""Local storage protections. A compromised OS account or administrator is out of scope."""

import os
import re
import stat
import subprocess
import sys
from pathlib import Path


def local_path(path: Path) -> Path:
    if ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise ValueError("local_path_required")
    absolute = path.absolute()
    for item in (*reversed(absolute.parents), absolute):
        try:
            info = item.stat(follow_symlinks=False)
        except FileNotFoundError:
            # SQLite can remove WAL/SHM sidecars as its last connection closes.
            # Inspect one metadata snapshot rather than exists() followed by stat().
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("linked_storage_not_supported")
        if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("reparse_storage_not_supported")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("linked_storage_not_supported")
    return absolute


def protect_directory(path: Path) -> Path:
    root = local_path(path)
    if root in (Path(root.anchor), Path.home(), Path.cwd()):
        raise ValueError("dedicated_data_directory_required")
    managed = {
        "security.sqlite3",
        "security.sqlite3-wal",
        "security.sqlite3-shm",
        "security.sqlite3-journal",
        "safe-mode",
    }
    if root.exists():
        for child in root.iterdir():
            if child.name not in managed and not re.fullmatch(
                r"before-jobs-v1-[0-9a-f]{32}\.sqlite3", child.name
            ):
                raise ValueError("dedicated_data_directory_required")
            local_path(child)
            if child.is_dir():
                raise ValueError("dedicated_data_directory_required")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform == "win32":
        # Fixed program, not a command assembled from a caller-controlled path.
        # The ACL contains only the current SID; this cannot exclude administrators
        # who can take ownership. Network/mapped drives are deliberately unsupported.
        script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:INCIDENT_SECURITY_DIRECTORY
$drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($path))
if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) { throw 'local disk required' }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
[System.IO.Directory]::SetAccessControl($path, $acl)
$actual = [System.IO.Directory]::GetAccessControl($path)
if (-not $actual.AreAccessRulesProtected) { throw 'inheritance enabled' }
$rules = $actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if ($rules.Count -ne 1 -or $rules[0].IdentityReference -ne $sid -or
    $rules[0].AccessControlType -ne 'Allow' -or
    $rules[0].FileSystemRights -ne 'FullControl') { throw 'unexpected access rules' }
foreach ($file in [System.IO.Directory]::EnumerateFiles($path)) {
    if ([System.IO.File]::Exists($file)) {
        if ([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) {
            throw 'linked file'
        }
        $fileAcl = New-Object System.Security.AccessControl.FileSecurity
        $fileAcl.SetOwner($sid)
        $fileAcl.SetAccessRuleProtection($true, $false)
        $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'Allow')))
        [System.IO.File]::SetAccessControl($file, $fileAcl)
        $actualRules = ([System.IO.File]::GetAccessControl($file)).GetAccessRules(
            $true, $true, [System.Security.Principal.SecurityIdentifier])
        if ($actualRules.Count -ne 1 -or $actualRules[0].IdentityReference -ne $sid) {
            throw 'unexpected file access rules'
        }
    }
}
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env={**os.environ, "INCIDENT_SECURITY_DIRECTORY": str(root)},
            capture_output=True,
            timeout=30,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode:
            raise OSError("private_directory_unavailable")
    else:
        root.chmod(0o700)
        info = root.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError("private_directory_unavailable")
        for backup in root.glob("before-jobs-v1-*.sqlite3"):
            private_file(backup)
    return root


def private_file(path: Path) -> Path:
    target = local_path(path)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        if sys.platform != "win32":
            info = target.stat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise OSError("private_file_required") from None
    else:
        os.close(descriptor)
    return target


def latch_safe_mode(root: Path) -> None:
    target = private_file(root / "safe-mode")
    with target.open("r+b") as stream:
        os.fsync(stream.fileno())
    if sys.platform != "win32":
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
