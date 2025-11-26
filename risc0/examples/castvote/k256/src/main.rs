use actix_web::{post, web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context, bail};
use alloy_sol_types::SolValue;
use risc0_zkvm::{
    default_prover, ExecutorEnv, ProverOpts, VerifierContext, InnerReceipt, sha::Digestible, compute_image_id, 
};
use hex;

// New imports for OpenAPI/Swagger
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use base64::{engine::general_purpose, Engine as _};
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
};
use sha2::{Sha256, Digest};

use k256_methods::{K256_VERIFY_ELF, K256_VERIFY_ID};

/// Struct for the request body
#[derive(Debug, Deserialize, ToSchema)] // ADD ToSchema
struct DiscloseRequest {
    #[schema(example = "{\n    \"id\": 123,\n    \"name\": \"Alice Wonderland\",\n    \"age\": 30,\n    \"is_student\": true\n}")]
    data: String,
    #[schema(example = 12345)]
    poll_id: u64,
}

/// Struct for the response body, now including the journal_abi_hex
#[derive(Debug, Serialize, ToSchema)] // ADD ToSchema
struct DiscloseResponse {
    #[schema(example = "0xabcdef123...")]
    seal_hex: String,
    #[schema(example = "0x11223344...")]
    journal_hex: String,
    #[schema(example = "0xaa55bb66...")]
    journal_abi_hex: String,
    #[schema(example = "0x8d5c4b...")]
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
fn disclose_logic(data: &str, poll_id: u64) -> Result<DiscloseResponse> {
    
    // Fixed private key for demonstration (Base64 encoded)
    let exported_private_key_string = "WatoiP9UiA3fqB08TVHjBGniYDXUz/04mAGRLb7tyQY=";

    let message_hash = Sha256::digest(&data); // Hash the message before signing

    println!("\n--- Signing Message ---");
    
    // --- NEW: Import Private Key from String ---
    println!("\n--- Importing Private Key ---");
    let imported_private_key_bytes_vec = general_purpose::STANDARD.decode(&exported_private_key_string)?;

    // Private keys for secp256k1 are 32 bytes (256 bits).
    let imported_private_key_array: [u8; 32] = imported_private_key_bytes_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::Error::msg("Failed to convert private key bytes to fixed-size array (expected 32 bytes)"))?;
    // Create a SigningKey from the raw bytes
    let imported_signing_key = SigningKey::from_bytes((&imported_private_key_array).into())?;
    // println!("Imported Signing Key (raw bytes): {:?}", imported_signing_key.to_bytes());

    let signature: Signature = imported_signing_key.sign(&message_hash);
    // println!("Signature (raw bytes): {:?}", signature.to_bytes());

    // 4. Export Signature to String (Base64)
    let exported_signature_string = general_purpose::STANDARD.encode(signature.to_bytes());

    // The input tuple for the guest program
    let input = (exported_signature_string, data, poll_id);

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

// 2. Define the OpenAPI structure with your API endpoint and schemas
#[derive(OpenApi)]
#[openapi(
    paths(disclose_handler), // List all handler functions here
    components(schemas(DiscloseRequest, DiscloseResponse)), // List all structs used as request/response bodies
    info(
        title = "RISC Zero ZK Prover API",
        description = "API for generating ZK proofs of K256 signature verification.",
        version = "1.0.0"
    ),
    tags(
        (name = "risc-zero", description = "RISC Zero ZK Proof Generation Endpoints")
    )
)]
struct ApiDoc;

/// Actix Web handler function for the /api/disclose endpoint
// 3. Decorate the handler with utoipa::path
#[utoipa::path(
    post,
    path = "/api/disclose",
    tag = "risc-zero",
    request_body = DiscloseRequest,
    responses(
        (status = 200, description = "ZK Proof generated successfully", body = DiscloseResponse),
        (status = 500, description = "Failed to generate proof")
    )
)]
#[post("/api/disclose")]
async fn disclose_handler(req: web::Json<DiscloseRequest>) -> impl Responder {
    println!("\nReceived request for Poll ID: {}", req.poll_id);
    match disclose_logic(&req.data, req.poll_id) {
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
    
    // Compute the OpenAPI documentation object
    let openapi = ApiDoc::openapi();

    match compute_image_id(K256_VERIFY_ELF) {
        Ok(digest) => println!("RISC-V Image ID (K256_VERIFY_ELF): {}", hex::encode(digest)),
        Err(e) => eprintln!("Warning: Could not compute Image ID: {}", e),
    }

    println!("🚀 Starting RISC Zero ZK Prover API server at http://127.0.0.1:3000");
    println!("📖 Swagger UI documentation available at http://127.0.0.1:3000/swagger-ui/"); // New URL

    HttpServer::new(move || {
        App::new()
            .service(disclose_handler)
            // 4. Add the Swagger UI service
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", openapi.clone()),
            )
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}