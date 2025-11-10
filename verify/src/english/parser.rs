// Parser for English contract text format
use super::*;
use anyhow::Result;

pub struct EnglishContractParser;

impl EnglishContractParser {
    pub fn new() -> Self {
        Self
    }
    
    /// Parse English contract from text
    pub fn parse(&self, text: &str) -> Result<EnglishContract> {
        let mut contract = EnglishContract {
            name: String::new(),
            description: String::new(),
            config: HashMap::new(),
            state: Vec::new(),
            functions: Vec::new(),
            events: Vec::new(),
        };
        
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            if line.starts_with("CONTRACT:") {
                contract.name = line.strip_prefix("CONTRACT:").unwrap().trim().to_string();
            } else if line.starts_with("DESCRIPTION:") {
                contract.description = line.strip_prefix("DESCRIPTION:").unwrap().trim().to_string();
            } else if line.starts_with("CONFIGURATION:") {
                i = self.parse_config(&lines, i + 1, &mut contract.config);
                continue;
            } else if line.starts_with("STATE VARIABLES:") {
                i = self.parse_state(&lines, i + 1, &mut contract.state);
                continue;
            } else if line.starts_with("FUNCTIONS:") {
                i = self.parse_functions(&lines, i + 1, &mut contract.functions);
                continue;
            } else if line.starts_with("EVENTS:") {
                i = self.parse_events(&lines, i + 1, &mut contract.events);
                continue;
            }
            
            i += 1;
        }
        
        Ok(contract)
    }
    
    fn parse_config(&self, lines: &[&str], start: usize, config: &mut HashMap<String, String>) -> usize {
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() || !line.starts_with('-') {
                break;
            }
            
            if let Some(content) = line.strip_prefix('-').map(|s| s.trim()) {
                if let Some((key, value)) = content.split_once(':') {
                    config.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
            
            i += 1;
        }
        i
    }
    
    fn parse_state(&self, lines: &[&str], start: usize, state: &mut Vec<StateVariable>) -> usize {
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() || !line.starts_with('-') {
                break;
            }
            
            if let Some(content) = line.strip_prefix('-').map(|s| s.trim()) {
                // Parse: name: type (description)
                let parts: Vec<&str> = content.split(':').collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim().to_string();
                    let rest = parts[1..].join(":");
                    
                    let (var_type, description) = if let Some(desc_start) = rest.find('(') {
                        let var_type = rest[..desc_start].trim().to_string();
                        let description = rest[desc_start + 1..].trim_end_matches(')').trim().to_string();
                        (var_type, description)
                    } else {
                        (rest.trim().to_string(), String::new())
                    };
                    
                    state.push(StateVariable {
                        name,
                        var_type,
                        description,
                        initial_value: None,
                    });
                }
            }
            
            i += 1;
        }
        i
    }
    
    fn parse_functions(&self, lines: &[&str], start: usize, functions: &mut Vec<ContractFunction>) -> usize {
        let mut i = start;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            // Look for function definitions (numbered or named)
            // Check for patterns like "1. FUNCTION:" or just "FUNCTION:"
            if (line.starts_with(|c: char| c.is_digit(10)) && line.contains("FUNCTION:")) 
                || line.starts_with("FUNCTION:") {
                let func = self.parse_single_function(lines, &mut i);
                functions.push(func);
            } else if line.starts_with("EVENTS:") {
                break;
            } else {
                i += 1;
            }
        }
        
        i
    }
    
    fn parse_single_function(&self, lines: &[&str], i: &mut usize) -> ContractFunction {
        let mut func = ContractFunction {
            name: String::new(),
            description: String::new(),
            parameters: Vec::new(),
            returns: Vec::new(),
            requirements: Vec::new(),
            steps: Vec::new(),
            visibility: Visibility::Public,
        };
        
        // Parse function name from first line
        let first_line = lines[*i].trim();
        if let Some(name_part) = first_line.split("FUNCTION:").nth(1) {
            func.name = name_part.trim().to_string();
        }
        
        *i += 1;
        
        // Parse function details
        while *i < lines.len() {
            let line = lines[*i].trim();
            
            // Stop at next function or EVENTS section
            if line.starts_with("EVENTS:") || 
               (line.starts_with(|c: char| c.is_digit(10)) && line.contains("FUNCTION:")) {
                break;
            }
            
            if line.starts_with("PARAMETERS:") || line.starts_with("Parameters:") {
                *i = self.parse_parameters(lines, *i + 1, &mut func.parameters);
                continue;
            } else if line.starts_with("RETURNS:") || line.starts_with("Returns:") {
                *i = self.parse_returns(lines, *i + 1, &mut func.returns);
                continue;
            } else if line.starts_with("REQUIREMENTS:") || line.starts_with("Requirements:") {
                *i = self.parse_list(lines, *i + 1, &mut func.requirements);
                continue;
            } else if line.starts_with("DO:") || line.starts_with("Steps:") || line.starts_with("Implementation:") {
                *i = self.parse_list(lines, *i + 1, &mut func.steps);
                continue;
            } else if line.starts_with("WHEN:") {
                // Skip WHEN lines, treat them as description
                *i += 1;
                continue;
            }
            
            *i += 1;
        }
        
        func
    }
    
    fn parse_parameters(&self, lines: &[&str], start: usize, params: &mut Vec<Parameter>) -> usize {
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() || !line.starts_with('-') {
                break;
            }
            
            if let Some(content) = line.strip_prefix('-').map(|s| s.trim()) {
                let parts: Vec<&str> = content.split(':').collect();
                if parts.len() >= 2 {
                    params.push(Parameter {
                        name: parts[0].trim().to_string(),
                        param_type: parts[1].trim().to_string(),
                        description: parts.get(2).map(|s| s.trim().to_string()).unwrap_or_default(),
                    });
                }
            }
            
            i += 1;
        }
        i
    }
    
    fn parse_returns(&self, lines: &[&str], start: usize, returns: &mut Vec<ReturnType>) -> usize {
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() || !line.starts_with('-') {
                break;
            }
            
            if let Some(content) = line.strip_prefix('-').map(|s| s.trim()) {
                let parts: Vec<&str> = content.split(':').collect();
                returns.push(ReturnType {
                    return_type: parts[0].trim().to_string(),
                    description: parts.get(1).map(|s| s.trim().to_string()).unwrap_or_default(),
                });
            }
            
            i += 1;
        }
        i
    }
    
    fn parse_list(&self, lines: &[&str], start: usize, list: &mut Vec<String>) -> usize {
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            
            // Stop at next section or function
            if line.starts_with("PARAMETERS:") || line.starts_with("RETURNS:") || 
               line.starts_with("REQUIREMENTS:") || line.starts_with("DO:") ||
               line.starts_with("EVENTS:") ||
               (line.starts_with(|c: char| c.is_digit(10)) && line.contains("FUNCTION:")) ||
               (!line.starts_with('-') && !line.is_empty()) {
                break;
            }
            
            if line.starts_with('-') {
                if let Some(content) = line.strip_prefix('-').map(|s| s.trim()) {
                    list.push(content.to_string());
                }
            }
            
            i += 1;
        }
        i
    }
    
    fn parse_events(&self, lines: &[&str], start: usize, events: &mut Vec<ContractEvent>) -> usize {
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() || !line.starts_with('-') {
                break;
            }
            
            if let Some(content) = line.strip_prefix('-').map(|s| s.trim()) {
                let name = content.split('(').next().unwrap_or(content).trim().to_string();
                events.push(ContractEvent {
                    name,
                    parameters: Vec::new(),
                });
            }
            
            i += 1;
        }
        i
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_simple_contract() {
        let text = r#"
CONTRACT: SimpleToken
DESCRIPTION: A basic token

FUNCTIONS:
1. FUNCTION: transfer
   PARAMETERS:
   - to: address
   - amount: u64
   REQUIREMENTS:
   - Sender must have balance
   DO:
   - Transfer tokens
"#;
        
        let parser = EnglishContractParser::new();
        let contract = parser.parse(text).unwrap();
        
        assert_eq!(contract.name, "SimpleToken");
        assert_eq!(contract.functions.len(), 1);
        assert_eq!(contract.functions[0].name, "transfer");
    }
}
