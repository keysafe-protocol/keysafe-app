extern crate sgx_types;
extern crate sgx_urts;
extern crate openssl;

use std::sync::Mutex;
use sgx_types::*;
use sgx_urts::SgxEnclave;

use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as fs;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern {
    fn exchange_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
}

fn init_enclave() -> SgxEnclave {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let sgxResult = SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr);
    match sgxResult {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            return r;
        },
        Err(x) => {
            panic!("[-] Init Enclave Failed {}!", x.as_str());
        },
    };
}

async fn app_seal_key(safeMessage: &SafeMessage) {
    println!("{}", safeMessage.secret);
}

async fn app_unseal_key(safeMessage: &SafeMessage) {
    println!("{}", safeMessage.secret);
}

#[derive(Deserialize, Serialize)]
struct SafeMessage {
    secret: String
}

struct AppState {
    enclave: SgxEnclave
}

#[get("/hello")]
async fn hello() -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Hello world!")
}

#[post("/exchange_key")]
async fn app_exchange_key(
    req_body: String,
    endex: web::Data<AppState>
) -> String {
    let e = &endex.enclave;
    println!("enclave id {}, user pub key {}.", e.geteid(), req_body);
    String::from("3082020a0282020100b7cccbf50ce04a3ba1faf4a58e078224a28c53c4901875aa62012d796261713852add6a839c6572829585048b91c5a632faa74ade49e567f0b9434a705e8d461971a18855834b7a1e7d5ce9e8db58294e9e55c1b3e5d289a14d63a3ee35d9a018b983d4b59617d05505222d2d94752e701d0a421ce4e7a287dd820381d57006d316e9ce10f6a89c2b2fff1ed82ebc3911119d93d3fd0248bc1b3d07fa8c3595b085426418633c36a59bce1346ef77584f04683bd9dff21a6e3fac93e04ce93d704be2aaf401fd410dfbbd15f8cee451dc97bee3bdda85d6ab12bc672791588b801f0d9fcc8780e76ca55c04cf546cbb607cb9b6a6b2dafed3a1502464f709ff48f6e31392e55ba7ee808dc663ed5ec7a91f90884c2554aeb6a44a5e6d36f7dcbcfcc5b74cf5679520ee0097929b1be6fb2cab6e12bf74b259335f7105b31511fa544c2006e7fa0409f6dad392bd4b51e07dbd5be3542f85c1bed274f001f253ffa953db45cac4b4e8949874aab68b6a2039bfad761e2b63fdbf4155916c82a55c673a147499eb905b1ec6282dc4bf9db31d8b44c396c3229f53100edc3ee6662e891e00008d287f10ba15ed78187561423bb496129e22859c551903a85666436dc9f48b82d373b549c7eb86367809c0386c6bc837e0f83c315fb7f43c88a02debd56b40a30a2139332f345c7458baf8505daea855e494e2aa2fa44a5bc57e9090203010001")
}

#[post("/seal")]
async fn seal(
    req_body: String,
    endex: web::Data<AppState>
) -> impl Responder {
    let e = &endex.enclave;
    HttpResponse::Ok().body(req_body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let edata: web::Data<AppState> = web::Data::new(AppState{
        enclave: init_enclave()
    });
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("certs/MyKey.key", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("certs/MyCertificate.crt").unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&edata))
            .service(app_exchange_key)
            .service(seal)
            .service(hello)
            .service(fs::Files::new("/", "./public"))
    })
    .bind_openssl("0.0.0.0:30001", builder)?
    .run()
    .await
}
