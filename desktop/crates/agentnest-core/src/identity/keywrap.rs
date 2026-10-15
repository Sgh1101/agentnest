//! Storage of secrets on disk with user-only permissions (docs/security.md 1.3 R1, 5).
//!
//! Phase 1 stores the TLS private key and `daemon.json` as **plain files readable only by the current user**
//! (POSIX `0600`; on Windows the inheritance is removed and only the user is granted access with `icacls`). The
//! deviation from "use the OS secret store" is the documented, user-confirmed risk R1. **DPAPI key wrapping is
//! Phase 3 and deliberately not implemented here**; the [`KeyStore`] trait is where it will plug in.
//!
//! The permission tooling sits behind [`FilePermissions`] so that the Windows-only `icacls` call never runs (or even
//! compiles) on other platforms and tests can use the plain `0600` implementation.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::redact::TlsKeyPem;

/// Restricts a file to the current user.
pub trait FilePermissions: Send + Sync {
    /// Makes `path` readable and writable only by the current user.
    fn restrict_to_current_user(&self, path: &Path) -> io::Result<()>;
}

/// The permission handling of the running platform: `chmod 0600` on Unix, `icacls` on Windows.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformPermissions;

impl FilePermissions for PlatformPermissions {
    #[cfg(unix)]
    fn restrict_to_current_user(&self, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }

    #[cfg(windows)]
    fn restrict_to_current_user(&self, path: &Path) -> io::Result<()> {
        // Remove inherited ACEs and grant only the current user full control. No shell is involved.
        let user = std::env::var("USERNAME").map_err(|_| {
            io::Error::new(io::ErrorKind::NotFound, "USERNAME is not set; cannot restrict the ACL")
        })?;
        let status = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{user}:F"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("icacls failed to restrict the file"))
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn restrict_to_current_user(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// Writes `bytes` to `path` so that the file is never readable by others: on Unix it is **created** with mode
/// `0600` (no window in which it is world readable), then the permission tooling runs (a no-op change on Unix, the ACL
/// step on Windows). The write is atomic (temporary file, then rename).
pub fn write_user_only(
    path: &Path,
    bytes: &[u8],
    perms: &dyn FilePermissions,
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        perms.restrict_to_current_user(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Where the TLS private key lives.
pub trait KeyStore: Send + Sync {
    /// The stored key, if any.
    fn load(&self) -> io::Result<Option<TlsKeyPem>>;
    /// Stores the key (replacing an existing one).
    fn store(&self, key: &TlsKeyPem) -> io::Result<()>;
    /// Deletes the key ("regenerate PC identity").
    fn delete(&self) -> io::Result<()>;
}

/// The Phase 1 key store: a PEM file with user-only permissions.
pub struct AclFileKeyStore {
    path: PathBuf,
    perms: Box<dyn FilePermissions>,
}

impl AclFileKeyStore {
    /// A store at `path` using the permission handling of this platform.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_permissions(path, Box::new(PlatformPermissions))
    }

    /// A store with explicit permission handling.
    pub fn with_permissions(path: impl Into<PathBuf>, perms: Box<dyn FilePermissions>) -> Self {
        Self {
            path: path.into(),
            perms,
        }
    }

    /// The key file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for AclFileKeyStore {
    fn load(&self) -> io::Result<Option<TlsKeyPem>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(TlsKeyPem::new(text))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn store(&self, key: &TlsKeyPem) -> io::Result<()> {
        write_user_only(&self.path, key.expose().as_bytes(), self.perms.as_ref())
    }

    fn delete(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn key_file_is_user_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = AclFileKeyStore::new(dir.path().join("identity").join("server-key.pem"));
        assert!(store.load().unwrap().is_none());
        store.store(&TlsKeyPem::new("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")).unwrap();
        let mode = std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the private key must not be readable by others");
        assert!(store.load().unwrap().unwrap().expose().contains("PRIVATE KEY"));
        // replacing keeps the mode
        store.store(&TlsKeyPem::new("second")).unwrap();
        let mode = std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(store.load().unwrap().unwrap().expose(), "second");
        store.delete().unwrap();
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn the_key_text_never_shows_up_in_debug_output() {
        let k = TlsKeyPem::new("SECRET-PEM-BYTES");
        assert!(!format!("{k:?}{k}").contains("SECRET"));
    }
}
