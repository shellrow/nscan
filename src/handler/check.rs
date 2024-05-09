use clap::ArgMatches;
use crate::dep;

pub fn check_dependencies(_arg: &ArgMatches) {
    let _ = dep::check_dependencies();
}
