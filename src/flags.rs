// Only call functions from within main.rs for corresponding user interface
//
// FLAG TO FUNCTION
// -a = add();
// -b = backup();
// -c = create();
// -C = change_vault_password();
// -d = delete();
// -D = delete_vault_all_files;
// -e = entropy(); not in use due to password safety
// -E = encrypt_and_exit() // NOT IN flags.rs //
// -g = gen_password();
// -p = change_password_account();
// -r = rename();
// -u = change_account_username();
use aes_gcm::{Aes256Gcm, aead::Aead};
use anyhow::{Context, Result};
use core::panic;
use input_handle::{get_string_input, get_u32_input};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use crate::{
    accounts::{build_accounts_file_path, read_accounts_from_file},
    crypto::generate_nonce,
    errors::exit_gracefully,
    json::{change_single_field, new_json_account, remove_account},
    password::generate_password,
    vault::{
        decrypt_vault, delete_vault, delete_vault_full, encrypt_and_exit, encrypt_vault,
        exit_vault, get_vault_location, print_vault_entries,
    },
};

const ENCRYPTED_EXTENSION: &str = ".tar.gz.gpg";
const BACKUP_EXTENSION: &str = ".bk";

// Creates a new vault
//
// USAGE (call before asking user what vault to access)
//
// create();
pub fn create() -> Result<()> {
    println!("FMP SETUP\n");
    println!("Creating .vault in home directory...\n");

    let vault_name = get_string_input("What should the vault be called? ");
    let vault_create_location = get_vault_location(Path::new(&vault_name));

    let encrypted_vault_location: PathBuf = vault_create_location.with_file_name(format!(
        "{}{}",
        vault_create_location.to_string_lossy(),
        ENCRYPTED_EXTENSION
    ));

    let accounts_location = vault_create_location.join("accounts");
    let mut user_input: String = String::new();

    if Path::new(&encrypted_vault_location).exists() {
        while !["y", "yes", "n", "no"].contains(&user_input.as_str()) {
            user_input = input_handle::get_string_input(
                "\nA vault with that name already exists, remove it? y(es), n(o)",
            )
            .to_lowercase();
        }

        if user_input == "y" || user_input == "yes" {
            println!("\nDecrypt the vault to remove it...\n");

            delete_vault_full(&vault_create_location, &encrypted_vault_location);
        } else {
            exit_vault(&vault_create_location);
        }
    }

    fs::create_dir(&vault_create_location)
        .with_context(|| format!("Failed to create directory {:?}", vault_create_location))?;

    println!("\nDone");
    println!("\nCreating accounts file...");

    File::create(&accounts_location)
        .with_context(|| format!("Failed to create account file {:?}", accounts_location))?;

    println!("\nDone\n");

    encrypt_and_exit(&vault_create_location);

    Ok(())
}

// Add an account to a vault
//
// USAGE (call after vault chose by user)
//
// add(vault_location);
pub fn add(vault: &PathBuf, cipher: &Aes256Gcm) {
    let mut user_input: String = "y".to_string();
    let nonce = generate_nonce();

    decrypt_vault(vault);

    while user_input == "y" || user_input == "yes" {
        let mut accounts = match read_accounts_from_file(&build_accounts_file_path(vault)) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading account file: {}", e);
                vec![]
            }
        };

        let mut name = input_handle::get_string_input("What should the account be named? ");
        let username = input_handle::get_string_input("\nWhat is the account username?");
        let password = cipher
            .encrypt(
                &nonce,
                input_handle::get_string_input("\nWhat is the account password").as_ref(),
            )
            .unwrap(); // TODO: Handle error and move away from get_string_input

        println!("\n");

        let mut error_handle = new_json_account(
            vault,
            name.as_str(),
            username.as_str(),
            &password,
            &mut accounts,
            cipher,
            &nonce,
        );

        while let Err(_e) = &error_handle {
            name = input_handle::get_string_input("Enter new account name: ");
            error_handle = new_json_account(
                vault,
                name.as_str(),
                username.as_str(),
                &password,
                &mut accounts,
                cipher,
                &nonce,
            );
        }

        user_input = String::new();

        while user_input != "y" && user_input != "yes" && user_input != "n" && user_input != "no" {
            user_input = input_handle::get_string_input(
                "\nWould you like to enter a new account? (y)es, (n)o",
            )
            .to_lowercase();

            println!("\n");
        }
    }

    encrypt_and_exit(vault);
}

// Remove account from vault
//
//USAGE (call after vault chose by user)
//
// delete(vault_location);
pub fn delete(vault: &PathBuf) {
    let mut user_input: String = "y".to_string();

    decrypt_vault(vault);

    while user_input == "y" || user_input == "yes" {
        let mut accounts = match read_accounts_from_file(&build_accounts_file_path(vault)) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading account file: {}", e);
                vec![]
            }
        };

        let mut name = input_handle::get_string_input("What account should be removed? ");

        println!("\n");

        let mut error_handle = remove_account(vault, name.as_str(), &mut accounts);

        while let Err(_e) = &error_handle {
            name = input_handle::get_string_input("Enter correct account name: ");
            error_handle = remove_account(vault, name.as_str(), &mut accounts);
        }

        user_input = String::new();

        while user_input != "y" && user_input != "yes" && user_input != "n" && user_input != "no" {
            user_input = input_handle::get_string_input(
                "\nWould you like to remove another account? (y)es, (n)o",
            )
            .to_lowercase();
            println!("\n");
        }
    }

    encrypt_and_exit(vault);
}

// Changes the password for an account in a vault
//
// USAGE (call after vault chose by user)
//
// change_account_password(vault_location);
pub fn change_account_password(vault: &PathBuf, cipher: &Aes256Gcm) {
    let nonce = generate_nonce();

    decrypt_vault(vault);

    let account = input_handle::get_string_input("What account password should be changed? ");
    let password = cipher
        .encrypt(
            &nonce,
            input_handle::get_string_input("\nWhat should the password be changed to?").as_ref(), // TODO: Move away from get_string_input
        )
        .unwrap(); // TODO: Handle error and move aWAY FROM 

    match change_single_field(
        vault, "password", "null", password, &account, cipher, &nonce,
    ) {
        Ok(()) => (),
        Err(e) => exit_gracefully(e),
    };

    encrypt_and_exit(vault);
}

// Changes the username for an account in a vault
//
// USAGE (call after vault chose by user)
//
// change_account_username(vault_location);
pub fn change_account_username(vault: &PathBuf, cipher: &Aes256Gcm) {
    let nonce = generate_nonce();

    decrypt_vault(vault);

    let account = input_handle::get_string_input("What account username should be changed? ");
    let username = input_handle::get_string_input("\nWhat should the username be changed to?");

    match change_single_field(
        vault,
        "username",
        username.as_str(),
        vec![0],
        &account,
        cipher,
        &nonce,
    ) {
        Ok(()) => (),
        Err(e) => exit_gracefully(e),
    };

    encrypt_and_exit(vault);
}

// Calculate the entropy of a password
//
// USAGE (call after vault chose by user)
//
// entropy(vault_location);
/*pub fn entropy(vault: String) {
    let password: String;
    // Ask user if they want to enter a password or use an already existing one
    let mut user_input = String::new();

    // Ask user if they want to calculate entropy for an existing password, or enter one
    while user_input != "e" && user_input != "enter" && user_input != "a" && user_input != "account" {
        user_input = get_string_input("Would you like to enter a password or use one linked to an account? (e)nter, (a)ccount");
        println!("");

    }

    // If user wants to enter a password
    if user_input == "e" || user_input == "enter" {
        // Get password to rate
        password = get_string_input("Enter the password for entropy calculation");
    }

    // If user wants to rate an existing password
    else {
        decrypt_vault(&vault);
        let mut account = get_string_input("What is the account for the password you want to rate?");
        println!("");
        let mut json = read_json(&vault, account);

        if let Ok(data) = &json {
            password = data.password.clone();
        }
        // If error is thrown from json();
        else {
            while let Err(e) = &json {
                println!("\n{}\n", e);
                account = get_string_input("What is the account for the password you want to rate?");
                json = read_json(&vault, account);
                println!("");
            }
            password = ("err").to_string();
        }

    }
    // Calculate entropy
    let entropy_tuple: (f64, &str) = calculate_entropy(&password);
    // Output
    println!("The password has {:.2} bits of entropy, giving it a rating of {}\n", entropy_tuple.0, entropy_tuple.1.to_lowercase());
    exit_vault(&vault);

} */

// Generate password and save to account if user chooses to TODO: Make sure password is always secret
//
// USAGE (call after vault chose by user)
//
// gen_password(vault_location);
pub fn gen_password(vault: &PathBuf, cipher: &Aes256Gcm) {
    let nonce = generate_nonce();

    let length = get_u32_input("How long should the password be? ");
    let generated_password = cipher
        .encrypt(&nonce, generate_password(length).as_ref())
        .unwrap(); // TODO: Handle error

    println!("\nPassword generated.");

    /*let binding = &generated_password.expose_secret().into();
    let entropy_tuple: (f64, &str) = calculate_entropy(&binding);
    println!("The password has {:.2} bits of entropy, giving it a rating of {}.\n", entropy_tuple.0, entropy_tuple.1.to_lowercase());*/

    let mut user_input: String = String::new();

    while !["y", "yes", "n", "no"].contains(&user_input.as_str()) {
        user_input =
            get_string_input("Would you like to save this password to an account? (y)es, (n)o")
                .to_lowercase();
    }

    if user_input == "y" || user_input == "yes" {
        decrypt_vault(vault);

        let mut accounts = match read_accounts_from_file(&build_accounts_file_path(vault)) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading account file: {}", e);
                vec![]
            }
        };

        let mut name = get_string_input("What should the account be named? ");
        let username = get_string_input("\nWhat is the account username?");
        let mut error_handle = new_json_account(
            vault,
            name.as_str(),
            username.as_str(),
            &generated_password,
            &mut accounts,
            cipher,
            &nonce,
        );

        while let Err(_e) = &error_handle {
            name = input_handle::get_string_input("What should the account be named: ");
            error_handle = new_json_account(
                vault,
                name.as_str(),
                username.as_str(),
                &generated_password,
                &mut accounts,
                cipher,
                &nonce,
            );
        }

        encrypt_and_exit(vault);
    }

    exit_vault(vault);
}

// Backup or install backup for vault
//
// USAGE (call after vault chose by user)
//
// backup(vault);
pub fn backup(vault: &PathBuf) -> Result<()> {
    let vault_location_as_encrypted_tar: PathBuf = vault.with_file_name(format!(
        "{}{}",
        vault.to_string_lossy(),
        ENCRYPTED_EXTENSION
    ));

    let vault_location_as_backup: PathBuf =
        vault_location_as_encrypted_tar.with_file_name(format!(
            "{}{}",
            vault_location_as_encrypted_tar.to_string_lossy(),
            BACKUP_EXTENSION
        ));

    let mut user_input: String = String::new();

    if user_input != "b" && user_input != "backup" && user_input != "i" && user_input != "install" {
        user_input = input_handle::get_string_input(
            "Would you like to create a backup or install a backup? (b)ackup, (i)nstall, (e)xit",
        );
    }

    if user_input == "b" || user_input == "backup" {
        if !Path::new(&vault_location_as_encrypted_tar).exists() {
            println!("No vault found in home directory. Has it been created?");
            exit_vault(vault);
        }

        fs::copy(&vault_location_as_encrypted_tar, &vault_location_as_backup).with_context(
            || {
                format!(
                    "Failed to copy {:?} to {:?}.",
                    vault_location_as_encrypted_tar, vault_location_as_backup
                )
            },
        )?;

        println!("\nSuccessfully backed up vault");
    } else if user_input == "i" || user_input == "install" {
        if !Path::new(&vault_location_as_backup).exists() {
            println!("No backup file found in home directory. Has it been created?");
            exit_vault(vault);
        }

        fs::copy(&vault_location_as_backup, &vault_location_as_encrypted_tar).with_context(
            || {
                format!(
                    "Failed to copy {:?} to {:?}.",
                    vault_location_as_backup, vault_location_as_encrypted_tar
                )
            },
        )?;

        println!("\nSuccessfully installed backup");
    }

    panic!("Unable to create backup for unknown reason, exiting as error is unrecoverable.");
}

// Delete full vault
//
// USAGE (call after vault chose by user)
//
// delete_vault_all_files(vault_location);
pub fn delete_vault_all_files(vault: &Path) {
    let vault_encrypted: PathBuf = vault.with_file_name(format!(
        "{}{}",
        vault.to_string_lossy(),
        ENCRYPTED_EXTENSION
    ));

    delete_vault_full(vault, &vault_encrypted);
}

// Renames vault
//
// USAGE (call after vault chose by user)
//
// rename(vault_location);
// FIXME: Prevent renaming to a vault that already exists
pub fn rename(vault: &Path) -> Result<()> {
    let mut new_name = get_string_input("What would you like to rename the vault to? ");
    let mut vault_new_directory = get_vault_location(&PathBuf::from(new_name));
    let mut vault_new_directory_encrypted: PathBuf = vault_new_directory.with_file_name(format!(
        "{}{}",
        vault_new_directory.to_string_lossy(),
        ENCRYPTED_EXTENSION
    ));

    let vault_old_encrypted: PathBuf = vault.with_file_name(format!(
        "{}{}",
        vault.to_string_lossy(),
        ENCRYPTED_EXTENSION
    ));

    let vault_old_encrypted_backup: PathBuf = vault_old_encrypted.with_file_name(format!(
        "{}{}",
        vault_old_encrypted.to_string_lossy(),
        BACKUP_EXTENSION
    ));

    while Path::new(&vault_new_directory_encrypted).exists() {
        let mut user_input = get_string_input(
            "Vault already exists, would you like to remove it? y(es), n(o), e(xit)",
        );

        while !["y", "yes", "n", "no", "e", "exit"].contains(&user_input.as_str()) {
            println!("\nInvalid input, please try again");
            user_input = get_string_input(
                "Vault already exists, would you like to remove it? y(es), n(o), e(xit)",
            );
        }

        if user_input == "y" || user_input == "yes" {
            delete_vault_full(&vault_new_directory, &vault_new_directory_encrypted);
        } else if user_input == "n" || user_input == "no" {
            println!("Enter new name:");

            new_name = get_string_input("What would you like to rename the vault to? ");
            vault_new_directory = get_vault_location(&PathBuf::from(new_name));
            vault_new_directory_encrypted = vault_new_directory.with_file_name(format!(
                "{}{}",
                vault_new_directory.to_string_lossy(),
                ENCRYPTED_EXTENSION
            ));
        } else {
            panic!("Exiting program");
        }
    }

    fs::rename(&vault, &vault_new_directory)
        .with_context(|| format!("Failed to copy {:?} to {:?}", vault, vault_new_directory))?;

    if Path::new(&vault_old_encrypted_backup).exists() {
        let vault_new_encrypted_backup: PathBuf = vault_new_directory.with_file_name(format!(
            "{}{}",
            vault_new_directory.to_string_lossy(),
            BACKUP_EXTENSION
        ));

        fs::rename(&vault_old_encrypted_backup, &vault_new_encrypted_backup).with_context(
            || {
                format!(
                    "Failed to copy {:?} to {:?}.",
                    vault_old_encrypted_backup, vault_new_encrypted_backup
                )
            },
        )?;
    }

    encrypt_and_exit(&vault_new_directory);

    Ok(())
}

// Change password to a vault
//
// USAGE (call after vault chose by user)
//
// change_vault_password(vault_location)
pub fn change_vault_password(vault: &PathBuf) {
    decrypt_vault(vault);

    println!("\nEnter new password:\n");

    encrypt_vault(vault);

    exit_vault(vault);
}

// If user does not enter any flags
//
// USAGE (call after vault chose by user)
//
// no_flags(vault_location)
pub fn no_flags(vault: &PathBuf) {
    decrypt_vault(vault);

    print_vault_entries(vault);

    delete_vault(vault);
}
