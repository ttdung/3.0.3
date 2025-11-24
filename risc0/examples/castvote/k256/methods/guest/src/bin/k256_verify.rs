// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use risc0_zkvm::guest::env;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use k256::elliptic_curve::sec1::FromEncodedPoint; // Trait for from_encoded_point

use k256::pkcs8::DecodePublicKey;
use k256::pkcs8::EncodePublicKey;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use base64::{engine::general_purpose};
use alloy_sol_types::SolValue;

use serde::{Serialize, Deserialize};
use bincode;
use serde_json::{Value};
#[derive(Serialize, Deserialize, Debug)]

struct revealInfo {
    nullifier: String,
    age: u32,
    is_student: bool,
    poll_id: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (base64_signature_str, message, poll_id) : (String, String, u64) = env::read();

    println!("START zkVM...");

    // 1. Import Verifying Key from String (for verification by another party)
    let exported_public_key_string= "BLZgb3PHEJ6B7Xta+jR4CEn1g3NluqLxNNRlrDfhPTbMATkwv04TOAJJMWuSlrtOfuO9SQNIdGeLlL+ppflRHN4=";
    let imported_public_key_bytes = general_purpose::STANDARD.decode(&exported_public_key_string)?;
    let verifying_key = VerifyingKey::from_encoded_point(
        &EncodedPoint::from_bytes(&imported_public_key_bytes)?
    )?;
    // println!("Imported Verifying Key (from string): {:?}", verifying_key.to_encoded_point(false).as_bytes());

    // 2. Hash the message (must be the exact same hashing algorithm as in Go)
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hashed_message = hasher.finalize();
    println!("Hashed Message (hex): {}", hex::encode(&hashed_message));

    let v: Value = serde_json::from_str(&message)?;
    println!("Person id {} name {} at age {} poll_id {}", v["id"], v["name"], v["age"], poll_id);

    // 3. Signature from Go (use the hex string from Go's output, which is ASN.1 DER)
    // let signature_base64 = "Hpev7tBpDDjBREQDp0yNwf/crqH2Pr1NVVm3p/KnjXRmFEneyKdTE5BcaCsNF4cpHVE7CNYgC++MoeOxqrNZbA=="
    println!("\n--- Importing and Verifying ---");
    let imported_signature_bytes = general_purpose::STANDARD.decode(&base64_signature_str)?;

    let imported_signature_array: [u8; 64] = imported_signature_bytes.as_slice().try_into()
    .map_err(|_| "Failed to convert signature bytes to fixed-size array")?; // Handle potential length mismatch

    let signature = Signature::from_bytes((&imported_signature_array).into())?;
    println!("Imported Signature (from string): {}", base64_signature_str);


    // 4. Verify the signature
    let verification_result = verifying_key.verify(&hashed_message, &signature);

    let mut rs = vec![0; 1];
    
    match verification_result {
        Ok(_) => {
            rs[0] = 1;
            println!("✅ Signature is valid!");
        },
        Err(e) => {
            rs[0] = 0;
            println!("❌ Signature verification failed: {}", e);
        },
    }
    assert_eq!(rs[0], 1, "{}", format!("signature is not valid {:?}", signature));
    
    // Calculate Nullifier = hash (salt, user_id, poll_id)
    let salt = "secret";
    let nullifier_str = format!("{}{}{}", salt, v["id"], poll_id);
    let mut nullifier_hasher = Sha256::new();
    nullifier_hasher.update(nullifier_str.as_bytes());
    let nullifier = nullifier_hasher.finalize();
    println!("Nullifier (hex): {}", hex::encode(&nullifier));

    // Create an instance of the struct
    let revealData = revealInfo {
        nullifier: hex::encode(&nullifier),
        age: v["age"].as_u64().unwrap() as u32,
        is_student: v["is_student"].as_bool().unwrap() as bool,
        poll_id: poll_id,
        // name: v["name"].as_str().unwrap().to_string(),
    };
    
    println!("revealData: {:?}", revealData);
    // Convert to Vec<u8> using bincode
    let encoded: Vec<u8> = bincode::serialize(&revealData).expect("Serialization failed");

    env::commit_slice(encoded.abi_encode().as_slice());
    Ok(())
}