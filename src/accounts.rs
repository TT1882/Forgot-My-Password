//! This file contains the functions to read and write to an accounts file.
//! It is used to manage the accounts in a vault.
//! It provides functions to build the path to the accounts file, read the accounts from the file, and write the accounts to the file.

use anyhow::{Context, Result};
use std::{fs, path::PathBuf};

/// Constructs the path to the 'accounts' file based on the input 'vault path'.
/// # Arguments:
/// * 'vault' - The name of the vault to find the accounts location for
///
/// # Returns:
/// * A 'PathBuf' containing the path of the accounts file.
pub fn build_accounts_file_path(vault: &PathBuf) -> PathBuf {
    vault.join("accounts")
}

/// Reads the file 'accounts' to a vector based on the input 'accounts path'.
/// # Arguments:
/// * 'accounts_path' - The location of the accounts file.
///
/// # Returns:
/// * A 'Result' containing a 'Vector' of account names on success and an 'Error' on failure.
pub fn read_accounts_from_file(accounts_path: &PathBuf) -> Result<Vec<String>> {
    let account_file_content = fs::read_to_string(accounts_path)
        .with_context(|| format!("Failed to read accounts file {:?}", accounts_path))?;

    let accounts: Vec<String> = account_file_content
        .lines()
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();

    Ok(accounts)
}

/// Writes an 'accounts' vector to an 'accounts' file.
///
/// # Arguments:
/// * 'accounts_path' - The location of the accounts file.
/// * 'accounts' - The vector of 'String' values containing the names to be written to the file.
///
/// # Returns:
/// * A 'Result' containing nothing on success and an 'Error' if the file cannot be written to.
pub fn write_accounts_to_file(accounts_path: &PathBuf, accounts: &[String]) -> Result<()> {
    fs::write(accounts_path, accounts.join("\n"))
        .with_context(|| format!("Failed to write to accounts file {:?}", accounts_path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_build_accounts_file_path() {
        let vault = PathBuf::from("/home/user/.vault");
        let accounts_path = build_accounts_file_path(&vault);

        assert_eq!(accounts_path, PathBuf::from("/home/user/.vault/accounts"));
    }

    #[test]
    fn test_read_accounts_from_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let accounts_path = PathBuf::from(temp_file.path());

        fs::write(&accounts_path, "Account1\nAccount2\nAccount3\n")
            .expect("Failed to write to account file");

        let accounts =
            read_accounts_from_file(&accounts_path).expect("Failed to read accounts file");

        assert_eq!(accounts, vec!["Account1", "Account2", "Account3"]);
    }

    #[test]
    fn test_write_accounts_to_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let accounts_path = PathBuf::from(temp_file.path());

        let accounts = vec![
            "Account1".to_string(),
            "Account2".to_string(),
            "Account3".to_string(),
        ];

        write_accounts_to_file(&accounts_path, &accounts)
            .expect("Failed to write to accounts file");

        let content = fs::read_to_string(&accounts_path).expect("Failed to read accounts file");

        assert_eq!(content.trim_end(), "Account1\nAccount2\nAccount3");
    }
}
