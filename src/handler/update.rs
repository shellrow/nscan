use clap::ArgMatches;
use crate::sys::dep;

pub fn check_dependencies(_arg: &ArgMatches) {
    dep::resolve_dependencies();
}
