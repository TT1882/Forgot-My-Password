//! This file contains all the functions for altering json files
//! It can read, update certain values and remove files

use crate::{
    accounts::{build_accounts_file_path, write_accounts_to_file},
    errors::exit_gracefully,
    vault::exit_vault,
};
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, aead::generic_array::typenum::U12};
use input_handle::get_string_input;
use serde::Deserialize;
use std::{
    fs::{self, File, create_dir_all, remove_dir_all},
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
};

// The structure of the data.json files
#[derive(Deserialize, Debug)]
pub struct UserPass {
    pub username: String,

    pub password: String,
}

/// Reads json file from username and vault file location.
///
/// # Arguments:
/// * "vault" - The path to the vault.
/// * "account" - The name of the account to read data from.
///
/// # Returns:
/// * On success - UserPass "json".
/// * On failure - Error, account name is incorrect.
///
/// # Panics:
/// * When the directory of the accounts data does not exist and on failure of code.
pub fn read_json(vault: &Path, account: String) -> Result<UserPass, Error> {
    let json_file_directory = vault.join(&account).join("data.json");

    if Path::new(&json_file_directory).exists() {
        match load_json_as_userpass(&json_file_directory) {
            Ok(data) => return Ok(data),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Unable to load '{:?}', it may be corrupted. Error: {}",
                        json_file_directory, e
                    ),
                ));
            }
        };
    }

    Err(Error::new(
        ErrorKind::NotFound,
        format!(
            "Account '{}' does not exist. Please check the name for typos or create a new account.",
            account
        ),
    ))
}

/// Creates new account
///
/// # Arguments:
/// * "vault" - The path to the vault.
/// * "name" - The name for the new account.
/// * "username" - The username for the new account.
/// * "password" - The password for the new account.
/// * "accounts" - List of accounts currently in the vault.
///
/// # Returns:
/// * On success - Nothing, all operations complete and no data is created.
/// * On failure - Exits as user wants to re-enter username.
///
/// # Panics:
/// * If an account with the name "username" already exists and on failure of code.
pub fn new_json_account(
    vault: &PathBuf,
    name: &str,
    username: &str,
    password: &Vec<u8>,
    accounts: &mut Vec<String>,
    cipher: &Aes256Gcm,
    nonce: &Nonce<U12>,
) -> Result<(), Error> {
    let new_account_dir = vault.join(name);
    let new_account_file = new_account_dir.join("data.json");
    let mut user_input: String = String::new();

    println!("Creating account...");

    if Path::new(&new_account_dir).exists() {
        // Gets user input
        while !["y", "yes", "n", "no", "e", "exit"].contains(&user_input.as_str()) {
            user_input = get_string_input("An Account with that name already exists, would you like to remove it? (y)es, (n)o, (e)xit").to_lowercase();
        }

        if user_input == "y" || user_input == "yes" {
            match remove_dir_all(&new_account_dir) {
                Ok(()) => (),
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Failed to remove directory '{:?}'. Error: {}",
                            new_account_file, e
                        ),
                    ));
                }
            }
        } else if user_input == "n" || user_input == "no" {
            return Err(Error::new(
                ErrorKind::Interrupted,
                "User chose to exit this function",
            ));
        } else {
            println!("Exiting...");
            exit_vault(vault);
        }
    }

    match create_dir_all(&new_account_dir) {
        Ok(()) => (),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to create directory '{:?}'. Error: {}",
                    new_account_dir, e
                ),
            ));
        }
    };

    match File::create(&new_account_file) {
        Ok(_o) => (),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to create file '{:?}'. Error: {}",
                    new_account_file, e
                ),
            ));
        }
    };

    match fs::write(&new_account_file, "{}") {
        Ok(()) => (),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to write to file '{:?}'. Error: {}",
                    new_account_file, e
                ),
            ));
        }
    };

    let mut json: serde_json::Value = match load_json_as_value(&new_account_file) {
        Ok(data) => data,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to load '{:?}' into serde_json. Error: {}",
                    &new_account_file, e
                ),
            ));
        }
    };

    json = add_fields_to_json(json, username, password, cipher, nonce);
    match save_json_file(&new_account_file, json) {
        Ok(()) => (),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to write to file '{:?}'. Error: {}",
                    new_account_file, e
                ),
            ));
        }
    };

    accounts.push(String::from(name));
    match write_accounts_to_file(&build_accounts_file_path(vault), accounts) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("Error: {}", e);
            e.chain()
                .skip(1)
                .for_each(|cause| eprintln!("because: {}", cause));
            std::process::exit(1);
        }
    }

    println!("\nSuccessfully saved new account");

    Ok(())
}

/// Saves json data to json file.
///
/// # Arguments:
/// * "json_file_directory" - The location of the file where the data is to be saved to.
/// * "json" - The JSON data to be saved.
///
/// # Returns:
/// * On success - Nothing, all operations complete and no data created.
/// * On failure - Nothing, finishes prematurely and program to be exited.
///
/// # Panics:
/// * On failure of code.
pub fn save_json_file(json_file_directory: &PathBuf, json: serde_json::Value) -> Result<(), Error> {
    let json_to_write = match serde_json::to_string(&json) {
        Ok(data) => data,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Failed to convert serde_json Value to String. Error: {}", e),
            ));
        }
    };

    let mut file = match File::create(json_file_directory) {
        Ok(data) => data,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to open file '{:?}'. Error: {}",
                    json_file_directory, e
                ),
            ));
        }
    };

    match file.write_all(json_to_write.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!(
                "Failed to write data to '{:?}'. Error: {}",
                json_file_directory, e
            ),
        )),
    }
}
/// Remove account from .vault
///
/// # Arguments:
/// * "vault" - The path to the vault
/// * "name" - The name of the account to remove.
/// * "accounts" - The list of accounts.
///
/// # Returns:
/// * On success - Nothing, all operations complete and no data created.
/// * On failure - Nothing, finishes prematurely and program to be exited.
///
/// # Panics:
/// * On failure of code.
pub fn remove_account(
    vault: &PathBuf,
    name: &str,
    accounts: &mut Vec<String>,
) -> Result<(), Error> {
    let location = vault.join(name);

    println!("Removing account...\n");

    if Path::new(&location).exists() {
        match remove_dir_all(&location) {
            Ok(()) => (),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to remove directory '{:?}'. Error: {}", location, e),
                ));
            }
        };

        accounts.retain(|accounts| *accounts != name);

        // NOTE
        match write_accounts_to_file(&build_accounts_file_path(&vault), accounts) {
            Ok(()) => (),
            Err(e) => exit_gracefully(e),
        }

        println!("\nSuccessfully removed account");

        Ok(())
    } else {
        println!("Account does not exist");
        Err(Error::new(
            ErrorKind::NotADirectory,
            format!(
                "Account '{}' does not exist. Make sure you spelled it right.",
                name
            ),
        ))
    }
}

/// Loads JSON file and returns its contents as a JSON Value.
///
/// # Arguments:
/// "json_file_directory" - The location of the file where the data is to be saved to.
///
/// # Returns:
/// * On success - Returns the contents of the JSON file as a serde_json Value.
/// * On failure - Nothing finishes prematurely and program to be exited.
///
/// # Panics:
/// * On failure of code.
pub fn load_json_as_value(json_file_directory: &PathBuf) -> Result<serde_json::Value, Error> {
    let json_as_string: String = match fs::read_to_string(json_file_directory) {
        Ok(data) => data,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to read file '{:?}'. Error: {}",
                    json_file_directory, e
                ),
            ));
        }
    };

    // Convert to json to serde json value
    match serde_json::from_str(&json_as_string) {
        Ok(data) => Ok(data),
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!("Failed to convert JSON to serde_json Value. Error: {}", e),
        )),
    }
}

/// Loads JSON file and returns its contents in the UserPass structure
///
/// # Arguments
/// * "json_file_directory" - The location of the file where the data is to be saved to.
///
/// # Returns:
/// * On success - Returns the contents of the JSON file as UserPass structure.
/// * On failure - Nothing, finishes prematurely and program to be exited.
///
/// # Panics:
/// * On failure of code.
pub fn load_json_as_userpass(json_file_directory: &PathBuf) -> Result<UserPass, Error> {
    let json_as_string: String = match fs::read_to_string(json_file_directory) {
        Ok(data) => data,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to read file '{:?}'. Error: {}",
                    json_file_directory, e
                ),
            ));
        }
    };

    // Convert to json to UserPass structure
    match serde_json::from_str(&json_as_string) {
        Ok(data) => Ok(data),
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!("Failed to convert JSON to UserPass. Error: {}", e),
        )),
    }
}

/// Changes the password of an account
///
/// # Arguments:
/// * "vault" - The path to the vault.
/// * "field" - The field to change.
/// * "username" - The username to be changed to if applicable.
/// * "password" - The password to be changed to if applicable.
/// * "account" - The name of the account to change.
///
/// # Returns:
/// * On success - Nothing, all operations complete and no data created.
/// * On failure - Nothing, finishes prematurely and program to be exited.
///
/// # Panics:
/// * On failure of code.
pub fn change_single_field(
    vault: &Path,
    field: &str,
    username: &str,
    password: Vec<u8>,
    account: &String,
    cipher: &Aes256Gcm,
    nonce: &Nonce<U12>,
) -> Result<(), anyhow::Error> {
    let json_file_directory = vault.join(account).join("data.json");
    let json: UserPass = match load_json_as_userpass(&json_file_directory) {
        Ok(data) => data,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to load json file '{:?}'. Error: {}",
                json_file_directory,
                e
            ));
        }
    };

    let username_original = json.username;
    let password_original = cipher.encrypt(&nonce, json.password.as_ref()).unwrap(); // TODO: Handle error
    let mut new_json: serde_json::Value = match serde_json::from_str("{}") {
        Ok(data) => data,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to create serde_json Value. Error: {}",
                e
            ));
        }
    };

    if field == "password" {
        new_json = add_fields_to_json(
            new_json,
            username_original.as_str(),
            &password,
            cipher,
            nonce,
        );
    } else if field == "username" {
        new_json = add_fields_to_json(new_json, username, &password_original, cipher, nonce);
    }

    match save_json_file(&json_file_directory, new_json) {
        Ok(()) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to save data.json file to {:?}. Error: {}",
            json_file_directory,
            e
        )),
    }
}

/// Adds username and password fields to json data.
///
/// # Arguments:
/// * "json" - The JSON data to be altered.
/// * "username" - The username to be added.
/// * "password" - The password to be added
///
/// # Returns:
/// * On success - The serde_json Value created
/// * On failure - Nothing, finishes prematurely and program to be exited.
///
/// # Panics:
/// * Never.
pub fn add_fields_to_json(
    mut json: serde_json::Value,
    username: &str,
    password: &Vec<u8>,
    cipher: &Aes256Gcm,
    nonce: &Nonce<U12>,
) -> serde_json::Value {
    json["username"] = serde_json::Value::String(username.to_owned());
    json["password"] = serde_json::Value::String(
        String::from_utf8(cipher.decrypt(&nonce, password.as_ref()).unwrap()).unwrap(),
    ); // TODO: Handle errors

    json
}
