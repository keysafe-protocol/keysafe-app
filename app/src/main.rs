extern crate sgx_types;
extern crate sgx_urts;
extern crate openssl;

use std::sync::Mutex;
use std::fs::File;
use std::fs;
use sgx_types::*;
use std::io::Write;
use sgx_urts::SgxEnclave;

use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as afs;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

static ENCLAVE_FILE: &'static str = "libenclave_ks.signed.so";

extern {

    fn ec_gen_key(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t
    ) -> sgx_status_t;

    fn ec_ks_exchange(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        strval: *mut char
    ) -> sgx_status_t;

    fn ec_ks_seal(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        some_string: *const char,
        strval: *mut char
    ) -> sgx_status_t;

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

fn init_enclave_and_genkey() -> SgxEnclave {
    let enclave = init_enclave();
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        ec_gen_key(enclave.geteid(), &mut retval);
    };
    return enclave;
}

struct AppState {
    enclave: SgxEnclave
}

#[derive(Deserialize)]
struct SealReq {
    pubkey: String,
    h: String,
    secret: String,
}

#[derive(Deserialize)]
struct NotifyReq {
    pubkey: String,
    t: String,
    cond: String
}

#[derive(Deserialize)]
struct ProveReq {
    pubkey: String,
    t: String,
    cond: String,
    code: String,
    h: String
}

fn sendmail(account: &str, msg: &str) {
    let email = Message::builder()
        .from("KS Admin <@qq.com>".parse().unwrap())
        .reply_to("KS Admin <@qq.com>".parse().unwrap())
        .to(format!("KS User<{}>", account).parse().unwrap())
        .subject("Confirmation Code")
        .body(String::from(msg))
        .unwrap();
    println!("sending mail {} to {}", msg, account);
    let creds = Credentials::new("@qq.com".to_string(), "".to_string());
    let mailer = SmtpTransport::relay("smtp.qq.com")
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {:?}", e),
    }
}

fn sendmsg(mobile: &str, msg: &str) {
    println!("sending msg {} to {}", msg, mobile);
}

async fn save_seal(e: &SgxEnclave, sealReq: &SealReq) {
    println!("{}", &sealReq.h);
    let mut file = File::create(&sealReq.h);
    match file {
        Ok(f) => { 
            write!(&f, "{}", sealReq.secret); 
            println!("successfully written to file");
        },
        Err(e) => println!("{}", e)
    } 
}

fn get_unseal(e: &SgxEnclave, filename: &String) -> String {
    let content = fs::read_to_string(filename)
        .expect("Something went wrong reading the file");
    return content;
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
    println!("{}", &sealReq.h);
    let e = &endex.enclave;
    // call enclave returns a string
    save_seal(e, &sealReq).await;
    HttpResponse::Ok().body("successful.")
}

#[post("/notify")]
async fn notify_user(
    notifyReq: web::Json<NotifyReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("notifying {}", &notifyReq.cond);
    let e = &endex.enclave;
    if notifyReq.t.eq("email") {
        // get confirm code from enclave
        sendmail(&notifyReq.cond, "123456");
    } else if notifyReq.t.eq("mobile") {
        // get confirm code from enclave
        sendmsg(&notifyReq.cond, "123456");
    }
    HttpResponse::Ok().body("confirm code sent")
}

#[post("/prove")]
async fn prove_user(
    proveReq: web::Json<ProveReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("proving {}", &proveReq.cond);
    let e = &endex.enclave;
    //generate a secret confirm code
    //send mail to notifyReq.mail
    HttpResponse::Ok().body("")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let edata: web::Data<AppState> = web::Data::new(AppState{
        enclave: init_enclave_and_genkey()
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
            .service(notify_user)
            .service(prove_user)
            .service(hello)
            .service(afs::Files::new("/", "./public"))
    })
    .bind_openssl("0.0.0.0:30001", builder)?
    .run()
    .await
}
