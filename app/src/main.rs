extern crate sgx_types;
extern crate sgx_urts;
extern crate openssl;

use std::sync::Mutex;
use std::fs::File;
use std::fs;
use sgx_types::*;
use std::io::Write;
use sgx_urts::SgxEnclave;
use std::str;
use std::ffi::CString;

use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as afs;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;


static ENCLAVE_FILE: &'static str = "libenclave_ks.signed.so";


extern {

    fn ec_gen_key(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t
    ) -> sgx_status_t;

    fn ec_ks_exchange(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        user_pub_key: *const c_char,
        strval: *mut c_void
    ) -> sgx_status_t;

    fn ec_ks_seal(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        some_string: *const c_char,
        strval: *mut c_void
    ) -> sgx_status_t;

    fn ec_ks_unseal(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        user_pub_key: *const c_char,
        sealed: *const c_char,
        code: *const u8
    ) -> sgx_status_t;

    fn ec_prove_me(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        code: *const u8,
        unsealed: *mut c_void
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
        ec_gen_key(enclave.geteid(), &mut retval)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => panic!("Enclave generate key-pair failed!")
    }
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
struct ExKeyReq {
    pubkey: String
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

async fn save_file(sealReq: &SealReq, val: Vec<u8>) {
    println!("{}", &sealReq.h);
    let file = File::create(&sealReq.h);
    match file {
        Ok(f) => { 
            let s = match str::from_utf8(&val[0..1024]) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            write!(&f, "{}", s); 
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
async fn exchange_key(
    exKeyReq: web::Json<ExKeyReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut plaintext = vec![0; 1024];
    println!("user pub key is {}", exKeyReq.pubkey);
    let result = unsafe {
        ec_ks_exchange(e.geteid(), &mut retval, 
            exKeyReq.pubkey.as_ptr() as *const c_char,
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => { 
            plaintext.resize(1024, 0);
            HttpResponse::Ok().body(plaintext)
        },
        _ => panic!("Exchange key failed!")
    }
}

#[post("/seal")]
async fn seal(
    sealReq: web::Json<SealReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("{}", &sealReq.h);
    println!("{}", &sealReq.secret);
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut plaintext = vec![0; 1024];
    let buffer = hex::decode(&sealReq.secret).expect("Decode Failed.");
    let result = unsafe {
        ec_ks_seal(e.geteid(), &mut retval,
            buffer.as_ptr() as *const c_char,
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            plaintext.resize(1024, 0);
            save_file(&sealReq, plaintext);
            HttpResponse::Ok().body("Seal Completed.")
        },
        _ => panic!("Seal failed!")
    }
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
            .service(exchange_key)
            .service(seal)
            .service(notify_user)
            .service(prove_user)
            .service(hello)
            .service(afs::Files::new("/", "./public"))
    })
    .bind_openssl("0.0.0.0:30000", builder)?
    .run()
    .await
}
