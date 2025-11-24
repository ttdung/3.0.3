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


use k256_methods::{K256_VERIFY_ELF, K256_VERIFY_ID};
// use aes_gcm::aead::{OsRng};
// use aes_gcm::{AeadCore, Aes256Gcm};
// use selective_disclosure_methods::{SELECTIVE_DISCLOSURE_ELF,SELECTIVE_DISCLOSURE_ID};
// use risc0_zkvm::{default_prover, ExecutorEnv};
use risc0_zkvm::{compute_image_id,default_prover, ExecutorEnv, ProverOpts, VerifierContext, InnerReceipt, sha::Digestible};
use std::fs::File;
use std::io::Write;
use anyhow::{Result, bail, Context};
use alloy_sol_types::SolValue;
use std::fs;
// use serde_json::{self}; // <--- ADD THIS LINE

use k256::{
    ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier},
    EncodedPoint,
};
// use rand_core::OsRng;
use base64::{engine::general_purpose, Engine as _};
use sha2::{Sha256, Digest};
use hex;
use clap::Parser;
// struct Person {
//     name: String,
//     age: u32,
//     is_student: bool,
// }

#[derive(Parser, Debug)]
#[command(name = "checkvote", version, about = "Verify a poll vote")]
struct Args {
    /// Input filename (e.g., a JSON or hex file)
    filename: String,

    /// Poll ID
    #[arg(long)]
    poll_id: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args = Args::parse();
    println!("{:?}", args);

    // Fixed private key for demonstration (Base64 encoded)
    let exported_private_key_string = "WatoiP9UiA3fqB08TVHjBGniYDXUz/04mAGRLb7tyQY=";

    // Fixed public key for demonstration (Base64 encoded)
    let exported_public_key_string= "BLZgb3PHEJ6B7Xta+jR4CEn1g3NluqLxNNRlrDfhPTbMATkwv04TOAJJMWuSlrtOfuO9SQNIdGeLlL+ppflRHN4=";
    
    // 3. Sign Message
    // /tmp/castvote/person.json
    let file_content = fs::read_to_string(args.filename).expect("Failed to read JSON file");

    // 2. Parse JSON into struct
    // let person: Person = serde_json::from_str(&file_content).expect("Failed to parse JSON");

    let message = file_content.clone();
    let message_hash = Sha256::digest(&message); // Hash the message before signing

    println!("\n--- Signing Message ---");
    println!("Message: {:?}", message);
    println!("Message Hash (hex): {}", hex::encode(&message_hash));
    
    // --- NEW: Import Private Key from String ---
    println!("\n--- Importing Private Key ---");
    let imported_private_key_bytes_vec = general_purpose::STANDARD.decode(&exported_private_key_string)?;

    // Private keys for secp256k1 are 32 bytes (256 bits).
    let imported_private_key_array: [u8; 32] = imported_private_key_bytes_vec
        .as_slice()
        .try_into()
        .map_err(|_| "Failed to convert private key bytes to fixed-size array (expected 32 bytes)")?;

    // Create a SigningKey from the raw bytes
    let imported_signing_key = SigningKey::from_bytes((&imported_private_key_array).into())?;
    // println!("Imported Signing Key (raw bytes): {:?}", imported_signing_key.to_bytes());

    let signature: Signature = imported_signing_key.sign(&message_hash);
    // println!("Signature (raw bytes): {:?}", signature.to_bytes());

    // 4. Export Signature to String (Base64)
    let exported_signature_string = general_purpose::STANDARD.encode(signature.to_bytes());
    println!("Exported Signature (Base64): {}", exported_signature_string);

    // 5. Import Signature from String
    println!("\n--- Importing signature and Verifying ---");
    let imported_signature_bytes = general_purpose::STANDARD.decode(&exported_signature_string)?;

    let imported_signature_array: [u8; 64] = imported_signature_bytes.as_slice().try_into()
    .map_err(|_| "Failed to convert signature bytes to fixed-size array")?; // Handle potential length mismatch

    let imported_signature = Signature::from_bytes((&imported_signature_array).into())?;
    // println!("Imported Signature (from string): {:?}", imported_signature.to_bytes());


    // 6. Import Verifying Key from String (for verification by another party)
    let imported_public_key_bytes = general_purpose::STANDARD.decode(&exported_public_key_string)?;
    let imported_verifying_key = VerifyingKey::from_encoded_point(
        &EncodedPoint::from_bytes(&imported_public_key_bytes)?
    )?;
    // println!("Imported Verifying Key (from string): {:?}", imported_verifying_key.to_encoded_point(false).as_bytes());

    // 7. Verify the Imported Signature using the Imported Verifying Key
    let is_valid = imported_verifying_key.verify(&message_hash, &imported_signature).is_ok();

    println!("\nSignature Verified: {}", is_valid);

    // Test with a tampered message
    let tampered_message = b"This is a tampered message.";
    let tampered_message_hash = Sha256::digest(tampered_message);
    let is_tampered_valid = imported_verifying_key.verify(&tampered_message_hash, &imported_signature).is_ok();
    println!("Signature verified with tampered message: {}", is_tampered_valid);

    let poll_id : u64 = args.poll_id;
    let _ = disclose(&exported_signature_string, &message, poll_id);

    Ok(())
}

fn disclose(signature: &str, data: &str, poll_id: u64) -> Result<()> {

    println!("signature {:?}", signature);
    println!("data {}", data);

    let input = (signature, data, poll_id);

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    println!("start prove ");
    // Produce a receipt by proving the specified ELF binary.
    // let receipt = prover.prove(env, K256_VERIFY_ELF).unwrap().receipt;

    let receipt = prover.prove_with_ctx(
        env,
        &VerifierContext::default(),
        K256_VERIFY_ELF,
        &ProverOpts::groth16(),
    )?
    .receipt;

    println!("start verify ");
    receipt.verify(K256_VERIFY_ID).unwrap();

    // Encode the seal with the selector.
    let seal = encode_seal(&receipt)?;

    // let seal_hex_string = vec_to_hex_string(&seal);
    println!("seal hex_string: {}", hex::encode(&seal));


    // Write seal to a file
    let mut file = File::create("/tmp/castvote/seal.dat").expect("failed to create file");
    file.write_all(hex::encode(&seal).as_bytes()).expect("failed to write");

    // Extract the journal from the receipt.
    let journal = receipt.journal.bytes.clone();

    // Decode Journal: Upon receiving the proof, the application decodes the journal to extract
    // the verified number. This ensures that the number being submitted to the blockchain matches
    // the number that was verified off-chain.


    println!("journal: {}", hex::encode(journal.clone()));

    // Write the journal to a file
    let mut file = File::create("/tmp/castvote/journal.dat").expect("failed to create file");
    file.write_all(hex::encode(journal.clone()).as_bytes()).expect("failed to write");

    let x = Vec::<u8>::abi_decode(&journal).context("decoding journal data")?;
    
    println!("journal abi_decode: {}", hex::encode(&x));

    // Write the journal abi to a file
    let mut file = File::create("/tmp/castvote/journal_abi.dat").expect("failed to create file");
    file.write_all(hex::encode(&x).as_bytes()).expect("failed to write");

    // Compute the Image ID
    let image_id = hex::encode(compute_image_id(K256_VERIFY_ELF)?);

    println!("Image ID: {}", image_id);

    // Write the image id to a file
    let mut file = File::create("/tmp/castvote/image_id.dat").expect("failed to create file");
    file.write_all(image_id.as_bytes()).expect("failed to write");    

    // // Dump receipe using serde
    // let receipt_json = serde_json::to_string_pretty(&receipt).unwrap();

    // // Write the JSON string to a file
    // let mut file = File::create("./res/receipt_selective_disclosure_groth16.json").expect("failed to create file");
    // file.write_all(receipt_json.as_bytes()).expect("failed to write");

    // println!("Data written to file successfully.");

    // receipt.journal.decode.unwrap();
    Ok(())
}

pub fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0u8; 4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
    };
    Ok(seal)
}
    