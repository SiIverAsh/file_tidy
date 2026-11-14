use file_tidy_platform::{freeze_migration_access, inspect, metadata_inventory};
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(windows)]
fn owner_access(path: &Path, mask: u32) -> TestResult {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: writable output slots and a metadata/security handle remain live.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    struct Descriptor(*mut std::ffi::c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo returned this owned LocalAlloc buffer.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _owned = Descriptor(descriptor);
    // SAFETY: the source owner's SID is contained in the live descriptor.
    let sid_bytes = unsafe { GetLengthSid(owner) } as usize;
    let size =
        std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>() - 4 + sid_bytes;
    let mut storage = vec![0u64; size.div_ceil(8)];
    let acl = storage.as_mut_ptr().cast::<ACL>();
    // SAFETY: aligned ACL storage covers the complete header and SID-bearing ACE.
    if unsafe { InitializeAcl(acl, size as u32, ACL_REVISION) } == 0
        || unsafe { AddAccessAllowedAce(acl, ACL_REVISION, mask, owner) } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the fixture owner, ACL and handle remain live until the API returns.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    Ok(())
}

fn metadata_only(path: &Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::*;
        owner_access(
            path,
            FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | WRITE_DAC | SYNCHRONIZE,
        )?;
    }
    Ok(())
}

fn readable(path: &Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    owner_access(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS,
    )?;
    Ok(())
}

#[test]
fn access_freeze_uses_metadata_rights_and_rejects_unreviewed_versions() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().canonicalize()?;
    let source = root.join("body");
    std::fs::write(&source, b"source-body-retained")?;
    let info = inspect(&source)?;
    let original = metadata_inventory(&source, &info)?;
    metadata_only(&source)?;
    #[cfg(windows)]
    assert!(std::fs::read(&source).is_err());
    let reviewed = metadata_inventory(&source, &info)?;
    assert_ne!(original.binding_bytes(), reviewed.binding_bytes());
    assert!(freeze_migration_access(&source, &info, &original, &|| Ok(())).is_err());
    assert_eq!(metadata_inventory(&source, &info)?, reviewed);
    assert!(
        freeze_migration_access(&source, &info, &reviewed, &|| {
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        })
        .is_err()
    );
    assert_eq!(metadata_inventory(&source, &info)?, reviewed);
    let frozen = freeze_migration_access(&source, &info, &reviewed, &|| Ok(()))?;
    assert_eq!(frozen.portable_bytes(), reviewed.portable_bytes());
    assert_eq!(metadata_inventory(&source, &info)?, frozen);
    #[cfg(windows)]
    assert!(std::fs::read(&source).is_err());
    readable(&source)?;
    assert_eq!(std::fs::read(&source)?, b"source-body-retained");
    Ok(())
}
