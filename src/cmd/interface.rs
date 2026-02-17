use crate::cli::InterfaceArgs;
use anyhow::Result;
use netdev::Interface;

/// Show network interfaces
pub fn show(args: &InterfaceArgs) -> Result<()> {
    let ifaces: Vec<Interface> = if args.all {
        // Show all interfaces
        let ifaces = netdev::get_interfaces();
        ifaces
    } else {
        // Show default interface
        let ifaces = match netdev::get_default_interface() {
            Ok(iface) => vec![iface],
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to get default interface: {}", e));
            }
        };
        ifaces
    };
    crate::output::interface::print_interface_tree(&ifaces);
    Ok(())
}
