use crate::ProvableVM;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use std::fs::File;
use std::io;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use crate::vm::{ExecutionCircuit};
use ark_serialize::CanonicalSerialize;

pub fn verify_proof(vk: &VerifyingKey<Bls12_381>, proof_file: &str, public_input: &[Fr]) -> bool {
    let proof = File::open(proof_file)
        .ok()
        .and_then(|mut file| Proof::deserialize_compressed(&mut file).ok());

    if let Some(proof) = proof {
        Groth16::<Bls12_381>::verify(vk, public_input, &proof).is_ok()
    } else {
        false
    }
}

pub fn generate_proof(
    vm: &ProvableVM,
    program: &[crate::vm::Instruction], // Instruction is in vm.rs
    trace_file: &str,
    proof_file: &str,
    pk: &ProvingKey<Bls12_381>,
) -> io::Result<()> {
    let trace_commitment = vm.generate_trace_commitment(trace_file)?;
    let initial_state = vm.trace.first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Trace is empty, no initial state")
    })?;
    let final_state = vm.trace.last().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Trace is empty, no final state")
    })?;

    let circuit = ExecutionCircuit {
        initial_state: initial_state.clone(),
        final_state: final_state.clone(),
        program: Vec::from(program),
        trace_commitment,
    };

    let mut rng = ChaCha20Rng::from_entropy();
    let proof = Groth16::<Bls12_381, LibsnarkReduction>::prove(pk, circuit, &mut rng)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut file = File::create(proof_file)?;
    proof
        .serialize_compressed(&mut file)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    println!("Proof written to '{}'", proof_file);
    Ok(())
}