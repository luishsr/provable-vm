use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::vm::{Instruction, Opcode};

pub fn load_program(file_path: &str) -> Result<Vec<Instruction>, String> {
    let file = File::open(file_path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);

    reader
        .lines()
        .filter_map(|line_res| {
            match line_res {
                Ok(line) => {
                    if line.starts_with('#') || line.trim().is_empty() {
                        return None; // Skip comments or empty lines
                    }

                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.is_empty() {
                        return None;
                    }

                    let opcode = match parts[0] {
                        "PUSH" => Some(Opcode::PUSH),
                        "POP" => Some(Opcode::POP),
                        "ADD" => Some(Opcode::ADD),
                        "SUB" => Some(Opcode::SUB),
                        "JMP" => Some(Opcode::JMP),
                        "JZ" => Some(Opcode::JZ),
                        "LOAD" => Some(Opcode::LOAD),
                        "STORE" => Some(Opcode::STORE),
                        "HALT" => Some(Opcode::HALT),
                        _ => return Some(Err(format!("Unknown opcode: {}", parts[0]))),
                    };

                    let operand = if parts.len() > 1 {
                        parts[1].parse::<u32>().map(Some).map_err(|e| e.to_string())
                    } else {
                        Ok(None)
                    };

                    match (opcode, operand) {
                        (Some(op), Ok(opr)) => Some(Ok(Instruction { opcode: op, operand: opr })),
                        (_, Err(err)) => Some(Err(err)),
                        _ => None,
                    }
                }
                Err(err) => Some(Err(err.to_string())),
            }
        })
        .collect()
}
