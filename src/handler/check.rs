use crate::dep;
use clap::ArgMatches;

pub fn check_dependencies(_arg: &ArgMatches) {
    match dep::check_dependencies() {
        Ok(_) => {
            println!("All dependencies are installed.");
            std::process::exit(0);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
