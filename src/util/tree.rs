pub fn node_label(label: &str, value: Option<&str>, delimiter: Option<&str>) -> String {
    match value {
        Some(value) => {
            let delimiter = match delimiter {
                Some(delimiter) => delimiter,
                None => ":",
            };
            //Tree::new(format!("{}{} {}", label, delimiter, value))
            format!("{}{} {}", label, delimiter, value)
        }
        None => {
            //Tree::new(label.to_string())
            label.to_string()
        }
    }
}
