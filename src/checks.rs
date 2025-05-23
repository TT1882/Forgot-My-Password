use anyhow::{Error, Result};
use std::path::{Path, PathBuf};
/// Checks if the current OS in use is Linux, as FMP is currently only supported on Linux.
///
/// # Arguments:
/// * 'os' - The OS to check against.
///
/// # Returns:
/// * A 'Result' containing nothing on success and an 'Error' if the OS is not Linux.
pub fn os_check(os: &str) -> Result<(), String> {
    if os != "linux" {
        Err("Sorry, fmp currently only supports Linux.".to_string())
    } else {
        Ok(())
    }
}

/// Checks if a vault exists with a given name.
///
/// # Arguments:
/// * 'vault' - The name of the vault to check.
///
/// # Returns:
/// * A 'Result' containing nothing on success and an 'Error' if the vault does not exist.
pub fn vault_exists_check(vault: impl AsRef<Path>) -> Result<(), Error> {
    let directory: PathBuf = vault
        .as_ref()
        .with_file_name(format!("{}.tar.gz.gpg", vault.as_ref().to_string_lossy()));

    if !Path::new(&directory).exists() {
        return Err(anyhow::anyhow!(
            "Vault {:?} not found! It can be created with 'fmp -c'",
            directory
        ));
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_os_check_success() {
        let os = "linux";
        let result = os_check(os);

        assert!(result.is_ok());
    }

    #[test]
    fn test_os_check_fail() {
        let os = "windows";
        let result = os_check(os);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Sorry, fmp currently only supports Linux.".to_string()
        );
    }

    #[test]
    fn test_os_check_empty() {
        let os = "";
        let result = os_check(os);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Sorry, fmp currently only supports Linux.".to_string()
        );
    }

    #[test]
    fn test_vault_exists_check_success() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");

        temp_file
            .persist("./vault.tar.gz.gpg")
            .expect("Failed to persist temp file");

        let vault_location = vault_exists_check(PathBuf::from("vault"));
        assert!(vault_location.is_ok());

        fs::remove_file("./vault.tar.gz.gpg").expect("Failed to remove temp file");
    }

    #[test]
    fn test_vault_exists_check_fail() {
        let vault_location = vault_exists_check(PathBuf::from(
            "i_do_not_exist_and_will_hopefully_throw_an_error",
        ));

        assert!(vault_location.is_err());
        assert_eq!(
            vault_location.unwrap_err().to_string(),
            "Vault \"i_do_not_exist_and_will_hopefully_throw_an_error.tar.gz.gpg\" not found! It can be created with 'fmp -c'"
        );
    }

    #[test]
    fn test_vault_exists_check_empty() {
        let vault_location = vault_exists_check(PathBuf::from(""));

        assert!(vault_location.is_err());
        assert_eq!(
            vault_location.unwrap_err().to_string(),
            "Vault \".tar.gz.gpg\" not found! It can be created with 'fmp -c'"
        );
    }

    #[test]
    fn test_vault_exists_check_special_characters() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");

        temp_file
            .persist("./vault_!@#$%^&*().tar.gz.gpg")
            .expect("Failed to persist temp file");

        let vault_location = vault_exists_check(PathBuf::from("vault_!@#$%^&*()"));
        assert!(vault_location.is_ok());

        fs::remove_file("./vault_!@#$%^&*().tar.gz.gpg").expect("Failed to remove temp file");
    }
}
