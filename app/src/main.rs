extern crate sgx_types;
extern crate sgx_urts;
extern crate openssl;

use std::sync::Mutex;
use std::fs::File;
use sgx_types::*;
use std::io::Write;
use sgx_urts::SgxEnclave;

use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as fs;

static ENCLAVE_FILE: &'static str = "libenclave_ks.signed.so";

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

struct AppState {
    enclave: SgxEnclave
}

#[derive(Deserialize)]
struct SealReq {
    pubkey: String,
    cond: String,
    secret: String,
}

async fn app_seal(e: &SgxEnclave, sealReq: &SealReq) {
    println!("{}", &sealReq.cond);
    let mut file = File::create(&sealReq.cond);
    match file {
        Ok(f) => { 
            write!(&f, "{}", sealReq.secret); 
            println!("successfully written to file");
        },
        Err(e) => println!("{}", e)
    } 
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
    String::from(" -----BEGIN RSA PUBLIC KEY-----
    MIIBhAKCAXsFp4OlxJzMM4Q5pbV+rz4lNK1EhEuW+nfkuqePOR6MY3Ujaqfy3ny2
    HJR9WoPYGKqsWseAvD8U0/vbnejMk05bQgd3eg8nq4ZY1jupkrBaVnliJt2vCZXa
    2a7gq8r+3l2I5GCAKR61vtm/rmaI0clyaShWSAVTWbG0W6kZCwJL67Jw+B6eBYtY
    LRojUwUMBS5YmTGLGgOrLINMev7rOng9hJWmVK98WgMdpbu7SDfgYU3Zsq1AbA5F
    zb4H/8A3pZv7uLNYtsL9aS6nx14OoHmMcu54gnFYKQ+XldCYqS72gCJf/vnAh/QQ
    q6fdFu9XF97ITDjJNAe4+SSAqV6H6DT1RzdbkUytpFpvtmA76fJOydOBwHXqAm+Q
    xC1NwqTeiOXQHFIQvSqKe1yM6RhjaQf7wSIFOkfivbpxS4X4/VPF+gxXfTW0bfBf
    a15IsV3vsBzu3kEKgsvWYRhTrX5byacxEP77iin2P6clLbo4GbWFERF93xuO0Q4l
    vEaNAgMBAAE=
    -----END RSA PUBLIC KEY-----")
}

#[post("/seal")]
async fn seal(
    sealReq: web::Json<SealReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("{}", &sealReq.cond);
    let e = &endex.enclave;
    // call enclave returns a string
    app_seal(e, &sealReq).await;
    HttpResponse::Ok().body("successful.")
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
