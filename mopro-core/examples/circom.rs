use mopro_core::middleware::circom::CircomState;
use num_bigint::{BigInt, ToBigInt};
use std::{collections::HashMap, str::FromStr};
use std::fs;
use serde_json;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Serialize, Deserialize, Debug)]
struct Input {
    raw_tbs_cert: Vec<i128>,
    mask: Vec<i128>,
    signature: Vec<i128>,
    modulus: Vec<i128>,
    message_padded_bytes: Vec<i128>,
    user_secret: Vec<i128>,
    start: Vec<i128>
}

fn convert_to_bigint(vec: Vec<i128>) -> Vec<BigInt> {
    vec.into_iter()
        .map(|num| BigInt::from(num))
        .collect()
}

fn main() -> Result<(), io::Error> {
    let wasm_path = "./examples/circom/selective-disclosure/selective-disclosure.wasm";
    let r1cs_path = "./examples/circom/selective-disclosure/selective-disclosure.r1cs";

    // Instantiate CircomState
    let mut circom_state = CircomState::new();

    // Setup
    let setup_res = circom_state.setup(wasm_path, r1cs_path);
    assert!(setup_res.is_ok());

    let _serialized_pk = setup_res.unwrap();

    // Deserialize the proving key and inputs if necessary

    let input_string = fs::read_to_string("./examples/circom/selective-disclosure/input.json")?;
    let input:Input = serde_json::from_str(&input_string)?;
    let raw_tbs_cert_input: Vec<BigInt> = convert_to_bigint(input.raw_tbs_cert);
    let mask_input: Vec<BigInt> = convert_to_bigint(input.mask);
    let modulus_input: Vec<BigInt> = convert_to_bigint(input.modulus);
    let signature_input: Vec<BigInt> = convert_to_bigint(input.signature);
    let message_padded_bytes_input: Vec<BigInt> = convert_to_bigint(input.message_padded_bytes);
    let user_secret_input: Vec<BigInt> = convert_to_bigint(input.user_secret);
    let start_input: Vec<BigInt> = convert_to_bigint(input.start);
    let mut inputs = HashMap::new();
    inputs.insert("rawTbsCert".to_string(), raw_tbs_cert_input);
    inputs.insert("mask".to_string(), mask_input);
    inputs.insert("message_padded_bytes".to_string(), message_padded_bytes_input);
    inputs.insert("signature".to_string(), signature_input);
    inputs.insert("modulus".to_string(), modulus_input);
    inputs.insert("userSecret".to_string(), user_secret_input);
    inputs.insert("start".to_string(), start_input);

    // Proof generation
    let generate_proof_res = circom_state.generate_proof(inputs);

    // Check and print the error if there is one
    if let Err(e) = &generate_proof_res {
        println!("Error: {:?}", e);
    }

    assert!(generate_proof_res.is_ok());

    let (serialized_proof, serialized_inputs) = generate_proof_res.unwrap();

    // Proof verification
    let verify_res = circom_state.verify_proof(serialized_proof, serialized_inputs);
    assert!(verify_res.is_ok());
    assert!(verify_res.unwrap()); // Verifying that the proof was indeed verified
    Ok(())
}
