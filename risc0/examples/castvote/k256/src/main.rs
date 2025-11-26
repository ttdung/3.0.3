use actix_web::{post, web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context, bail};
use alloy_sol_types::SolValue;
use risc0_zkvm::{
    default_prover, ExecutorEnv, ProverOpts, VerifierContext, InnerReceipt, sha::Digestible, compute_image_id, 
};
use hex;

use k256_methods::{K256_VERIFY_ELF, K256_VERIFY_ID};

/// Struct for the request body
#[derive(Debug, Deserialize)]
struct DiscloseRequest {
    signature: String,
    data: String,
    poll_id: u64,
}

/// Struct for the response body, now including the journal_abi_hex
#[derive(Debug, Serialize)]
struct DiscloseResponse {
    seal_hex: String,
    journal_hex: String,
    journal_abi_hex: String,
    image_id_hex: String,
}

/// Helper function to encode the receipt seal with its selector (from your original code)
fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0u8; 4];
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
    };
    Ok(seal)
}

/// The core disclosure logic to run the ZK Prover and collect outputs
fn disclose_logic(signature: &str, data: &str, poll_id: u64) -> Result<DiscloseResponse> {
    
    // The input tuple for the guest program
    let input = (signature, data, poll_id);

    let env = ExecutorEnv::builder()
        .write(&input)
        .context("Failed to write input to environment")?
        .build()
        .context("Failed to build executor environment")?;

    let prover = default_prover();

    // 1. Generate the ZK Proof (Receipt)
    let receipt = prover.prove_with_ctx(
        env,
        &VerifierContext::default(),
        K256_VERIFY_ELF,
        &ProverOpts::groth16(),
    )?
    .receipt;

    // Verify the receipt against the expected Image ID
    let expected_image_id_digest = risc0_zkvm::sha::Digest::from(K256_VERIFY_ID);
    receipt.verify(expected_image_id_digest).context("Receipt verification failed against K256_VERIFY_ID")?;

    // 2. Collect Outputs
    let seal = encode_seal(&receipt)?;
    let journal = receipt.journal.bytes.clone();
    
    // Decode the journal bytes using ABI format (as Vec<u8> was committed by the guest)
    let journal_abi_decoded = Vec::<u8>::abi_decode(&journal)
        .context("Failed to abi_decode journal bytes into Vec<u8>")?;

    // Compute the image ID for the response
    let image_id = compute_image_id(K256_VERIFY_ELF)?;

    // 3. Return the results
    Ok(DiscloseResponse {
        seal_hex: hex::encode(&seal),
        journal_hex: hex::encode(&journal),
        journal_abi_hex: hex::encode(&journal_abi_decoded), 
        image_id_hex: hex::encode(image_id),
    })
}

/// Actix Web handler function for the /api/disclose endpoint
#[post("/api/disclose")]
async fn disclose_handler(req: web::Json<DiscloseRequest>) -> impl Responder {
    println!("\nReceived request for Poll ID: {}", req.poll_id);
    match disclose_logic(&req.signature, &req.data, req.poll_id) {
        Ok(response) => {
            println!("Proof generated successfully.");
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            eprintln!("🔥 Error during disclosure process: {:?}", e);
            // Respond with a 500 Internal Server Error
            HttpResponse::InternalServerError().body(format!("Failed to generate proof: {}", e))
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    
    // It's highly recommended to compute the Image ID once and verify it here:
    match compute_image_id(K256_VERIFY_ELF) {
        Ok(digest) => println!("RISC-V Image ID (K256_VERIFY_ELF): {}", hex::encode(digest)),
        Err(e) => eprintln!("Warning: Could not compute Image ID: {}", e),
    }

    println!("🚀 Starting RISC Zero ZK Prover API server at http://127.0.0.1:3000");

    HttpServer::new(|| {
        App::new()
            .service(disclose_handler)
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}