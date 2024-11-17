use ark_bls12_381::{Bls12_381, Fr};
use std::fs::File;
use std::io::{self, ErrorKind};
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn convert_commitment_to_field(commitment: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(commitment)
}

pub fn load_vk(file_path: &str, pk: &ProvingKey<Bls12_381>) -> io::Result<VerifyingKey<Bls12_381>> {
    if let Ok(mut file) = File::open(file_path) {
        VerifyingKey::deserialize_compressed(&mut file)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    } else {
        println!("Verifying key file not found. Generating a new one...");

        let vk = pk.vk.clone();
        let mut file = File::create(file_path)?;
        vk.serialize_compressed(&mut file)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        println!("Verifying key saved to '{}'", file_path);
        Ok(vk)
    }
}
