use mopro_core::middleware::circom::CircomState;
use num_bigint::{BigInt, ToBigInt};
use std::{collections::HashMap, str::FromStr};

fn convert_strings_to_bigints(strings: &[&str]) -> Vec<BigInt> {
    strings
        .iter()
        .filter_map(|s| BigInt::from_str(s).ok())
        .collect()
}

fn main() {
    let wasm_path = "./examples/circom/selective-disclosure/selective-disclosure.wasm";
    let r1cs_path = "./examples/circom/selective-disclosure/selective-disclosure.r1cs";

    // Instantiate CircomState
    let mut circom_state = CircomState::new();

    // Setup
    let setup_res = circom_state.setup(wasm_path, r1cs_path);
    assert!(setup_res.is_ok());

    let _serialized_pk = setup_res.unwrap();

    // Deserialize the proving key and inputs if necessary

    let rawTbsCert:[i128; 2048] = [];
    let mask:[i128; 2048] = [];
    let signature:[i128; 17] = [];
    let modulus:[i128; 17] = [
        2484169357657323362007096172928199247,
        973376856245558529002289264138464558,
        2573667960324822418189539657656118492,
        1637861581831737991506235706821641165,
        662683113709696374396984693561724347,
        2124330996009504225379546653809671984,
        2315718606664992965162561298723398178,
        1949517824954314231360162536496682229,
        1245027244975903722007098129903593696,
        2190012828576758270576876936993063062,
        1503942223052772990763350204412957554,
        2242888805346983534803190474825204259,
        2047912361949285891751251090080429683,
        1222286395247408026633054735831271075,
        1828945271258195033895637222224313317,
        203294729875443317791291878502235800,
        3400194974695320678796595877787478
    ];
    // Prepare inputs
    let mut inputs = HashMap::new();
    let raw_tbs = rawTbsCert.iter().map(
        |&s| s.to_bigint().unwrap()
    ).collect();
    inputs.insert("rawTbsCert".to_string(), raw_tbs);
    let mask_input = mask.iter().map(
        |&s| s.to_bigint().unwrap()
    ).collect();
    inputs.insert("mask".to_string(), mask_input);
    let sig = signature.iter().map(
        |&s| s.to_bigint().unwrap()
    ).collect();
    inputs.insert("message_padded_bytes".to_string(), vec![ ().to_bigint().unwrap() ]);
    inputs.insert("signature".to_string(), sig);
    let modulus_input = modulus.iter().map(
        |&s| s.to_bigint().unwrap()
    ).collect();
    inputs.insert("modulus".to_string(), modulus_input);
    inputs.insert("userSecret".to_string(), vec![ ().to_bigint().unwrap() ]);
    inputs.insert("start".to_string(), vec![ ().to_bigint().unwrap() ]);

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
}
