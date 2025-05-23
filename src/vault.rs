use crate::{
    accounts::{build_accounts_file_path, read_accounts_from_file},
    checks::vault_exists_check,
    json::{UserPass, read_json},
};
use input_handle::get_string_input;
use prettytable::{Table, row};
use std::{
    path::{Path, PathBuf},
    process::{Command, exit},
};

// Gets vault from user, should only be called once at main
//
// USAGE
//
// let vault_location = vault_to_access();
pub fn vault_to_access() -> PathBuf {
    let mut vault_to_be_accessed: PathBuf =
        get_string_input("What vault should be accessed? ").into();

    let mut vault_exists = vault_exists_check(&get_vault_location(&vault_to_be_accessed));

    while let Err(e) = &vault_exists {
        println!("\nError: {}\n", e);
        vault_to_be_accessed = get_string_input("What vault should be accessed? ").into();
        vault_exists = vault_exists_check(&get_vault_location(&vault_to_be_accessed));
    }

    println!("\n");

    get_vault_location(&vault_to_be_accessed)
}

// Finds where vault is
//
// USAGE
//
// let var: String = get_vault_location(&vault);
pub fn get_vault_location(vault_name: &Path) -> PathBuf {
    let home_dir = dirs::home_dir().expect("Could not find home directory!");
    home_dir.join(format!(".{}", vault_name.display()))
}

// Encrypts the .vault file to .vault.tar.gz.gpg
//
// USAGE
//
// encrypt_vault(&vault_location);
pub fn encrypt_vault(vault: &Path) {
    let vault_as_encrypted_tar: PathBuf =
        vault.with_file_name(format!("{}.tar.gz.gpg", vault.to_string_lossy()));

    let vault_as_tar: PathBuf = vault.with_file_name(format!("{}.tar.gz", vault.to_string_lossy()));

    println!("Encrypting vault...\n");

    if Path::new(&vault_as_encrypted_tar).exists() {
        Command::new("rm")
            .arg(vault_as_encrypted_tar.to_string_lossy().to_string())
            .output()
            .expect("Could not remove encrypted file");
    }

    Command::new("tar")
        .args([
            "-czf",
            &vault_as_tar.to_string_lossy(),
            &vault.to_string_lossy(),
        ])
        .output()
        .expect("Failed to execute command");

    Command::new("gpg")
        .args(["-c", "--no-symkey-cache", &vault_as_tar.to_string_lossy()])
        .output()
        .expect("Could not encrypt vault, please run fmp -E to encrypt");

    while !vault_as_encrypted_tar.exists() {
        encrypt_dnc(&vault_as_tar);
    }

    Command::new("rm")
        .args(["-r", &vault_as_tar.to_string_lossy()])
        .output()
        .expect("Could not remove file");

    Command::new("rm")
        .args(["-r", &vault.to_string_lossy()])
        .output()
        .expect("Could not remove file");

    println!("Encrypted!");
}

// Decrypts the .vault.tar.gz.gpg file to .vault
//
// USAGE
//
// decrypt_vault(&vault_location);
pub fn decrypt_vault(vault: &Path) {
    let mut attempts: u32 = 0;
    let vault_as_encrypted_tar: PathBuf =
        vault.with_file_name(format!("{}.tar.gz.gpg", vault.to_string_lossy()));

    let vault_as_tar: PathBuf = vault.with_file_name(format!("{}.tar.gz", vault.to_string_lossy()));

    println!("Decrypting vault...\n");

    Command::new("gpg")
        .args([
            "-q",
            "--no-symkey-cache",
            &vault_as_encrypted_tar.to_string_lossy(),
        ])
        .output()
        .expect("Could not encrypt vault");

    while !Path::new(&vault_as_tar).exists() {
        println!("Incorrect credentials! Try again.\n");
        attempts = rate_limit(&mut attempts);
        decrypt_dnc(&vault_as_encrypted_tar);
    }

    Command::new("tar")
        .args(["-xf", &vault_as_tar.to_string_lossy(), "-C", "/"])
        .output()
        .expect("Failed to execute command");

    Command::new("rm")
        .arg(vault_as_tar.to_string_lossy().to_string())
        .output()
        .expect("Could not remove tarball vault");

    println!("Decrypted\n");
}

// Reads all json files and prints to screen
//
// USAGE
//
// print_vault_entries(&vault_location)
pub fn print_vault_entries(vault: &PathBuf) {
    let accounts = match read_accounts_from_file(&build_accounts_file_path(&vault)) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading account file: {}", e);
            vec![]
        }
    };

    if accounts.is_empty() {
        println!("No accounts have been created! Use fmp -a to create an account.");
        return;
    }

    let mut table = Table::new();
    table.add_row(row!["Account", "Username", "Password"]);

    for i in 0..accounts.len() {
        let account = accounts[i].clone();
        let json = match read_json(vault, account) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading json file: {}", e);

                UserPass {
                    username: "e".to_string(),
                    password: "e".to_string(),
                }
            }
        };

        table.add_row(row![accounts[i], json.username, json.password]);
    }

    table.printstd();
}

// Removes the vault folder
//
// USAGE
//
// delete_vault(&vault_location)
pub fn delete_vault(vault: &PathBuf) {
    if Path::new(&vault).exists() {
        Command::new("rm")
            .args(["-r", &vault.to_string_lossy()])
            .output()
            .expect("Could not remove .vault");
    }
}

// Exits the vault and program
//
// USAGE
//
// exit(&vault_location)
pub fn exit_vault(vault: &PathBuf) {
    delete_vault(vault);

    exit(1);
}

// Encrypts the vault any tidy's files up
//
// USAGE
//
// encrypt_and_exit(&vault_location);
pub fn encrypt_and_exit(vault: &PathBuf) {
    encrypt_vault(vault);

    delete_vault(vault);

    exit_vault(vault);
}

// Removes all files related to a vault
//
// USAGE
//
// delete_vault_full(&vault_location, &vault_location_encrypted)
pub fn delete_vault_full(vault: &Path, vault_encrypted: &Path) {
    decrypt_vault(vault);

    Command::new("rm")
        .arg(vault_encrypted.to_string_lossy().to_string())
        .output()
        .expect("Failed to remove old vault");

    Command::new("rm")
        .args(["-r", &vault.to_string_lossy()])
        .output()
        .expect("Failed to remove old vault");
}

pub fn rate_limit(attempts: &mut u32) -> u32 {
    *attempts += 1;

    if *attempts > 3 {
        panic!("Too many attempts! Exiting...");
    } else {
        attempts.clone()
    }
}

// DO NOT CALL
//
// REASON
//
// This function is a workaround to weird behavior with gpg in while loops.
fn decrypt_dnc(vault_as_encrypted_tar: &Path) {
    Command::new("gpg")
        .args([
            "-q",
            "--no-symkey-cache",
            &vault_as_encrypted_tar.to_string_lossy(),
        ])
        .output()
        .expect("Could not encrypt vault");
}

// DO NOT CALL
//
// REASON
//
// This function is a workaround to weird behavior with gpg in while loops.
fn encrypt_dnc(vault_as_tar: &Path) {
    Command::new("gpg")
        .args(["-c", "--no-symkey-cache", &vault_as_tar.to_string_lossy()])
        .output()
        .expect("Could not encrypt vault, please run fmp -E to encrypt");
}
