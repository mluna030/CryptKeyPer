use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use cryptkeyper::parameters::{XmssParameterSet};
use cryptkeyper::{XmssOptimized, XmssSignatureOptimized, XmssPublicKeyOptimized};
use cryptkeyper::xmss::xmss_optimized::XmssPrivateState;
use bincode;
use sha2::{Sha256, Digest};
use base64;

// --- Request and Response Structs ---

#[derive(Debug, Serialize, Deserialize)]
pub struct XmssKeyGenRequest {
    pub parameter_set: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmssKeyGenResponse {
    pub public_key: XmssPublicKeyOptimized,
    pub private_key_state: String, // Base64 encoded bincode of XmssPrivateState
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmssVerifyRequest {
    pub message: String,
    pub signature: XmssSignatureOptimized,
    pub public_key: XmssPublicKeyOptimized,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmssVerifyResponse {
    pub is_valid: bool,
}

// --- API Endpoints ---

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello CryptKeyper API!")
}

#[post("/xmss/keygen")]
async fn xmss_keygen(req: web::Json<XmssKeyGenRequest>) -> HttpResponse {
    let param_set = match req.parameter_set.as_str() {
        "XmssSha256W16H10" => XmssParameterSet::XmssSha256W16H10,
        "XmssSha256W16H16" => XmssParameterSet::XmssSha256W16H16,
        "XmssSha256W16H20" => XmssParameterSet::XmssSha256W16H20,
        _ => return HttpResponse::BadRequest().body("Invalid parameter set".to_string()),
    };

    match XmssOptimized::new(param_set) {
        Ok(xmss) => {
            let public_key = xmss.public_key.clone();
            let private_state = (*xmss.private_state().read()).clone();
            let encoded_private_state = bincode::serialize(&private_state).unwrap();
            let private_key_state = base64::encode(encoded_private_state);

            HttpResponse::Ok().json(XmssKeyGenResponse { public_key, private_key_state })
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Key generation failed: {:?}", e)),
    }
}

#[post("/xmss/verify")]
async fn xmss_verify(req: web::Json<XmssVerifyRequest>) -> HttpResponse {
    let message_hash = Sha256::digest(req.message.as_bytes()).to_vec();

    match XmssOptimized::verify(&message_hash, &req.signature, &req.public_key) {
        Ok(is_valid) => HttpResponse::Ok().json(XmssVerifyResponse { is_valid }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Verification failed: {:?}", e)),
    }
}

// --- Main Application ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new()
            .service(hello)
            .service(xmss_keygen)
            .service(xmss_verify)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
