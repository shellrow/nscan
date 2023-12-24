use std::fs::read_to_string;

pub fn read_port_list(file_path: String) -> Result<Vec<u16>, String> {
    let data = read_to_string(file_path);
    let text = match data {
        Ok(content) => content,
        Err(_) => {
            return Err("Failed to read file".to_string());
        }
    };
    let port_list: Vec<&str> = text.trim().split("\n").collect();
    let mut ports: Vec<u16> = Vec::new();
    for port in port_list {
        match port.parse::<u16>() {
            Ok(p) => {
                ports.push(p);
            }
            Err(_) => {}
        }
    }
    Ok(ports)
}

pub fn read_word_list(file_path: String) -> Result<Vec<String>, String> {
    let data = read_to_string(file_path);
    let text = match data {
        Ok(content) => content,
        Err(_) => {
            return Err("Failed to read file".to_string());
        }
    };
    let word_list: Vec<&str> = text.trim().split("\n").collect();
    let mut words: Vec<String> = Vec::new();
    for word in word_list {
        words.push(word.to_string());
    }
    Ok(words)
}
