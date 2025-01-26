use clap::Parser;

mod account;
mod json;
mod password;
mod vault; use vault::{vault_to_access, encrypt_and_exit};
mod checks; use checks::os_check;
mod flags; use flags::{add, backup, change_account_password, change_account_username, create, delete, entropy, gen_password, no_flags};
#[derive(Debug, Parser)]
struct Options {

    /// Add an account to vault.
    /// used as: -a, --add
    #[clap(short = 'a', long = "add")]
    flag_a: bool,

    /// Backup vault or install backup
    /// user as -b, --backup
    #[clap(short = 'b', long = "backup")]
    flag_b: bool,

    /// Create vault.
    /// used as -c --create-vault
    #[clap(short = 'c', long = "create-vault")]
    flag_c: bool,

    /// Delete account from vault.
    /// used as: -d, --delete
    #[clap(short = 'd', long = "delete")]
    flag_d: bool,

    /// Calculate password entropy.
    /// used as -e --entropy
    #[clap(short = 'e', long = "entropy")]
    flag_e: bool,

    /// Generate new password.
    /// used as -g --generate-pasword
    #[clap(short = 'g', long = "generate-password")]
    flag_g: bool,

    /// Encrypt vault.
    /// used as -E, --encrypt
    #[clap(short = 'E', long = "encrypt")]
    flag_en: bool,

    /// Change password for an account.
    /// used as: -p , --change-password 
    #[clap(short = 'p', long = "change-password")]
    flag_p: bool,

    /// Change username for an account.
    /// used as: -u , --change-username 
    #[clap(short = 'u', long = "change-username")]
    flag_u: bool,
}

fn main() {
    // Check users current os
    os_check();
    // Stores flag user input bools
    let opts = Options::parse();

    // If flag -c or --create is used NOTE: must be above vault location
    if opts.flag_c == true {
        create();
    }
    // Gets vault location from user
    let vault_location = vault_to_access();

    // If flag -a or --add is used
    if opts.flag_a == true {
        add(&vault_location);
    }

    // If flag -d or --delete is used
    if opts.flag_d == true {
        delete(&vault_location);
    }

    // If flag -p or --change-password is used
    if opts.flag_p == true {
        change_account_password(&vault_location);
    }

    // If flag -u or --change-username is used
    if opts.flag_u == true {
        change_account_username(&vault_location);
    }

    // If flag -e or --entropy is used
    if opts.flag_e == true {
        entropy()
    }

    // If flag -g or --generate-pasword is used
    if opts.flag_g == true {
        gen_password(&vault_location);
    }

    // If flag -E or --encrypt is used
    if opts.flag_en == true {
        encrypt_and_exit(&vault_location);
    }

    // If flag -b or --backup is used
    if opts.flag_b == true {
        backup(&vault_location);
    }
    // If no flags are supplied
    no_flags(&vault_location);
}