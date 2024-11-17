mod vm;
mod program_loader;
mod utils;
mod zk_proof;

use vm::{ProvableVM, ExecutionCircuit};
use program_loader::load_program;
use utils::{convert_commitment_to_field, load_vk};
use zk_proof::{verify_proof};
use ark_bls12_381::{Fr, Bls12_381};
use ark_groth16::{Groth16};
use ark_snark::CircuitSpecificSetupSNARK;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {

    // Path to files
    let vk_path = "program.vk"; // Verifying key file path
    let proof_path = "program.proof"; // Proof file path

    // Run the VM and generate proof
    let mut vm = ProvableVM::new();
    let program = load_program("program.prov").expect("Failed to load program");

    // Run program and generate trace
    vm.run_program(&program, "program.trace").expect("Failed to execute program");

    // Create circuit
    let circuit = ExecutionCircuit {
        initial_state: vm.trace.first().unwrap().clone(),
        final_state: vm.trace.last().unwrap().clone(),
        program: program.clone(),
        trace_commitment: vm.generate_trace_commitment("program.trace").expect("Failed to generate trace commitment"),
    };

    // Generate proving and verifying keys
    let mut rng = ChaCha20Rng::from_entropy();
    let (pk, _) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut rng).unwrap();

    // Generate proof
    vm.generate_proof(&program, "program.trace", proof_path, &pk).expect("Failed to generate proof");

    // Load verifying key
    let vk = load_vk(vk_path, &pk).expect("Failed to load verifying key");

    // Prepare public inputs
    let public_inputs: Vec<Fr> = vec![
        convert_commitment_to_field(&circuit.trace_commitment),
    ];

    // Verify proof
    let valid = verify_proof(&vk, proof_path, &public_inputs);

    if valid {
        println!("Proof is valid!");
    } else {
        println!("Proof is invalid.");
    }
}
