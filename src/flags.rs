use input_handle::get_string_input;
use std::{path::Path, process::{Command, exit}};
use crate::{vault::{get_vault_location, exit_vault, encrypt_and_exit, decrypt_vault, print_vault_entries, delete_vault}, account::{read_account, get_account_location}, json::{new_json_account, remove_account, change_password, change_username}, password::{calculate_entropy, generate_password}};

pub fn create() {
    println!("FMP SETUP\n");
    println!("Creating .vault in home directory...\n");
    // Get user to name vault
    let vault_name = get_string_input("What should the vault be called? ");
    // Format variables
    let vault_create_location = &get_vault_location(&vault_name);
    let encrypted_vault_location = format!("{}/.tar.gz.gpg", vault_create_location);
    let accounts_loaction = format!("{}/accounts", vault_create_location);
    let mut user_input:String = String::new();
    // If encrypted vault exists
    if Path::new(&encrypted_vault_location).exists() {
        // Ask user for input, handles incorect input
        if user_input != "y" && user_input != "yes" && user_input != "no" && user_input != "n" {
            user_input = input_handle::get_string_input("A vault with that name already exists, remove it? y(es), n(o)").to_lowercase();
        }
        // Remove vault
        if user_input == "y" || user_input == "yes" {
            Command::new("rm")
                .arg(encrypted_vault_location.as_str()).output().expect("Failed to remove old vault");
        }
        // Exit
        else {
            exit_vault(vault_create_location);
        }
    }
    // Make .vault folder
    Command::new("mkdir")
        .arg(&vault_create_location.as_str()).output().expect("Failed to make .vault folder");
    println!("Done");
    println!("Creating accounts file...\n");
    // Create accounts file
    Command::new("touch")
        .arg(accounts_loaction.as_str()).output().expect("Failed to make account file");
    println!("Done\n");
    // Exit
    encrypt_and_exit(vault_create_location);
}


pub fn add(vault: &String) {
    let mut user_input: String = "y".to_string();
        // Decrypt vault
        decrypt_vault(vault);
        while user_input == "y" || user_input == "yes" {
            let account = read_account(get_account_location(vault));
            // Get user inputs
            let mut name = input_handle::get_string_input("What should the account be named? ");
            let username = input_handle::get_string_input("\nWhat is the account username?");
            let password = input_handle::get_string_input("\nWhat is the account password");
            println!("");
            // Create new account
            let mut error_handle = new_json_account(vault, name.as_str(), username.as_str(), password.as_str(), account.clone());
            // Handle error
            while error_handle != "ok" {
                name = input_handle::get_string_input("Enter new account name: ");
                error_handle = new_json_account(vault, name.as_str(), username.as_str(), password.as_str(), account.clone());
            }
            // Ask user if they would like to add a new account
            user_input = String::new();
            while user_input != "y" && user_input != "yes" && user_input != "n" && user_input != "no" {
                user_input = input_handle::get_string_input("\nWould you like to enter a new account? (y)es, (n)o").to_lowercase();
                println!("");
            }
        }
        // Exit
        encrypt_and_exit(vault);
}

pub fn delete(vault: &String) {
    let mut user_input: String = "y".to_string();
        // Decrypt vault
        decrypt_vault(vault);
        while user_input == "y" || user_input == "yes" {
            let account = read_account(get_account_location(vault));
            // Get account name
            let mut name = input_handle::get_string_input("What account should be removed? ");
            println!("");
            // Removes account 
            let mut error_handle = remove_account(vault, name.as_str(), account.clone());
            // Handle error
            while error_handle != "ok" {
                name = input_handle::get_string_input("Enter correct account name: ");
                error_handle = remove_account(vault, name.as_str(), account.clone());
            }
            // Ask user if they would like to remove another account
            user_input = String::new();
            while user_input != "y" && user_input != "yes" && user_input != "n" && user_input != "no" {
                user_input = input_handle::get_string_input("\nWould you like to remove another account? (y)es, (n)o").to_lowercase();
                println!("");
            }
        }
        // Exit
        encrypt_and_exit(vault);
}

pub fn change_account_password(vault: &String) {
    // Decrypt vault
    decrypt_vault(vault);
    // Get user input
    let name = input_handle::get_string_input("What account password should be changed? ");
    let password = input_handle::get_string_input("\nWhat should the password be changed to?");
    // Changes password
    change_password(vault, password.as_str(), &name);
    // Exit
    encrypt_and_exit(vault);
}

pub fn change_account_username(vault: &String) {
    // Decrypt vault
    decrypt_vault(vault);
    // Get user input
    let name = input_handle::get_string_input("What account username should be changed? ");
    let username = input_handle::get_string_input("\nWhat should the username be changed to?");
    // Change username
    change_username(vault, &username.as_str(), &name);
    // Exit
    encrypt_and_exit(vault);
}

pub fn entropy() {
    // Get password to rate
    let password: String = input_handle::get_string_input("Enter the password for entropy calculation");
    // Calculate entropy
    let entropy_tuple: (f64, &str) = calculate_entropy(&password);
    println!("The password has {:.2} bit entropy, giving it a rating of {}", entropy_tuple.0, entropy_tuple.1);
}

pub fn gen_password(vault: &String) {
    // Gets wanted length from user
    let length = input_handle::get_u32_input("How long should the password be? ");
    // Generate password of that length
    let generated_password = generate_password(length);
    let mut user_input: String = String::new();
    // Ask user if they want to save password to account
    while user_input != "y" && user_input != "yes" && user_input != "n" && user_input != "no" {
        user_input = get_string_input("Would you like to save this password to an account? (y)es, (n)o").to_lowercase();
    }
    // If they do
    if user_input == "y" || user_input == "yes" {
        // Get user inputs
        let account = read_account(get_account_location(vault));
        let name = get_string_input("What should the account be named? ");
        let username = get_string_input("\nWhat is the account username?");
        // Create new account
        new_json_account(vault, name.as_str(), username.as_str(), &generated_password, account);
        // Exit
        encrypt_and_exit(vault);
    }
    // Exit
    exit_vault(vault);
}

pub fn backup(vault: &String) {
    let vault_location_as_encrypted_tar = format!("{}.tar.gz.gpg", vault);
        let vault_location_as_backup = format!("{}.bk", vault_location_as_encrypted_tar);
        // Ask user if they want to create or install backup
        let mut user_input: String = String::new();
        // Input validation
        if user_input != "b" && user_input != "backup" && user_input != "i" && user_input != "install" {
            user_input = input_handle::get_string_input("Would you like to create a backup or install a backup? (b)ackup, (i)nstall");
        }
        // If user wants to backup
        if user_input == "b" || user_input == "backup" {
            // Check that encrypted vault exists
            if Path::new(&vault_location_as_encrypted_tar).exists() == false {
                // If it does not exist
                println!("No vault found in home directory. Has it been created?");
                exit_vault(vault);
            }
            // Backup
            Command::new("cp")
                .args([vault_location_as_encrypted_tar.as_str(), vault_location_as_backup.as_str()]).output().expect("Could not create backup");
            println!("\nSuccessfully backed up vault");
        }
        // If user wants to install backup
        else {
            // Check if backup exists
            if Path::new(&vault_location_as_backup).exists() == false {
                // If it does not
                println!("No backup file found in home directory. Has it been created?");
                exit_vault(vault);
            }
            // Install backup
            Command::new("cp")
                .args([vault_location_as_backup.as_str(), vault_location_as_encrypted_tar.as_str()]).output().expect("Could not install backup");
            println!("\nSuccessfully installed backup");
        }
        exit(1);
}

pub fn no_flags(vault: &String) {
    decrypt_vault(vault);
    print_vault_entries(vault);
    delete_vault(vault);
}