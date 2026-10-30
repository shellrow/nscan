use crate::cli::InterfaceArgs;
use anyhow::Result;
use netdev::Interface;

/// Show network interfaces
pub fn show(
    args: &InterfaceArgs,
    no_stdout: bool,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    let ifaces: Vec<Interface> = if args.all {
        // Show all interfaces

        netdev::get_interfaces()
    } else {
        // Show default interface

        match netdev::get_default_interface() {
            Ok(iface) => vec![iface],
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to get default interface: {}", e));
            }
        }
    };
    if !no_stdout {
        crate::output::interface::print_interface_tree(&ifaces);
    }
    if let Some(path) = output {
        crate::util::json::save_json_output(&ifaces, &path, crate::util::json::JsonStyle::Pretty)?;
    }
    Ok(())
}
