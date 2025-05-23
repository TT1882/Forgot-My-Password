use clap::Parser;
use std::env;

mod accounts;
mod crypto;
mod errors;
mod json;
mod password;
mod vault;
use vault::{encrypt_and_exit, vault_to_access};
mod checks;
use checks::os_check;
mod flags;

use crypto::generate_cipher;
use errors::exit_gracefully;
use flags::{
    add, backup, change_account_password, change_account_username, change_vault_password, create,
    delete, delete_vault_all_files, gen_password, no_flags, rename,
};

#[derive(Debug, Parser)]
struct Options {
    /// Add an account to vault.
    /// used as: -a, --add
    #[clap(short = 'a', long = "add")]
    flag_a: bool,

    /// Backup vault or install backup
    /// used as -b, --backup
    #[clap(short = 'b', long = "backup")]
    flag_b: bool,

    /// Create vault.
    /// used as -c, --create-vault
    #[clap(short = 'c', long = "create-vault")]
    flag_c: bool,

    /// Change vault password.
    /// used as -C, --change-vault-password
    #[clap(short = 'C', long = "change-vault-password")]
    flag_cvp: bool,

    /// Delete account from vault.
    /// used as: -d, --delete
    #[clap(short = 'd', long = "delete")]
    flag_d: bool,

    /// Delete vault.
    /// used as: -D, --delete
    #[clap(short = 'D', long = "delete-vault")]
    flag_dv: bool,

    /*/// Calculate password entropy.
    /// used as -e, --entropy
    #[clap(short = 'e', long = "entropy")]
    flag_e: bool,*/
    /// Encrypt vault.
    /// used as -E, --encrypt
    #[clap(short = 'E', long = "encrypt")]
    flag_en: bool,

    /// Generate new password.
    /// used as -g, --generate-password
    #[clap(short = 'g', long = "generate-password")]
    flag_g: bool,

    /// Change password for an account.
    /// used as: -p, --change-password
    #[clap(short = 'p', long = "change-password")]
    flag_p: bool,

    /// Rename vault.
    /// used as: -r, --rename-vault
    #[clap(short = 'r', long = "rename-vault")]
    flag_r: bool,

    /// Change username for an account.
    /// used as: -u  --change-username
    #[clap(short = 'u', long = "change-username")]
    flag_u: bool,
}

fn main() {
    // Check users current os
    match os_check(env::consts::OS) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }

    let cipher = generate_cipher();

    // Stores flag user input bools
    let opts = Options::parse();

    // If flag -c or --create is used NOTE: must be above vault location incase no vault exists
    if opts.flag_c {
        match create() {
            Ok(()) => (),
            Err(e) => exit_gracefully(e),
        }
    }
    // Gets vault location from user
    let vault_location = vault_to_access();

    // If flag -a or --add is used
    if opts.flag_a {
        add(&vault_location, &cipher);
    }
    // If flag -d or --delete is used
    else if opts.flag_d {
        delete(&vault_location);
    }
    // If flag -p or --change-password is used
    else if opts.flag_p {
        change_account_password(&vault_location, &cipher);
    }
    // If flag -u or --change-username is used
    else if opts.flag_u {
        change_account_username(&vault_location, &cipher);
    }
    // If flag -e or --entropy is used
    /*if opts.flag_e {
        entropy(&vault_location)
    }*/
    // If flag -g or --generate-password is used
    else if opts.flag_g {
        gen_password(&vault_location, &cipher);
    }
    // If flag -E or --encrypt is used
    else if opts.flag_en {
        encrypt_and_exit(&vault_location);
    }
    // If flag -b or --backup is used
    else if opts.flag_b {
        match backup(&vault_location) {
            Ok(()) => (),
            Err(e) => exit_gracefully(e),
        }
    }
    // If flag -D or --delete-vault is used
    else if opts.flag_dv {
        delete_vault_all_files(&vault_location);
    }
    // If flag -r or --rename-vault is used
    else if opts.flag_r {
        match rename(&vault_location) {
            Ok(()) => (),
            Err(e) => exit_gracefully(e),
        }
    }
    // If flag -C or --change-vault-password
    else if opts.flag_cvp {
        change_vault_password(&vault_location);
    }
    // If no flags are supplied
    else {
        no_flags(&vault_location);
    }
}
