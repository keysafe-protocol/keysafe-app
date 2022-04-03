extern crate sgx_types;
extern crate sgx_urts;
extern crate openssl;
#[macro_use]
extern crate log;
extern crate log4rs;

use std::sync::Mutex;
use std::fs::File;
use std::fs;
use std::path::Path;
use sgx_types::*;
use std::io::Write;
use sgx_urts::SgxEnclave;
use std::str;
use std::ffi::CString;
use std::ffi::CStr;

use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as afs;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;

use log::{error, info, warn};
use glob::glob;

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
        strval: *mut c_void,
        strval2: *mut c_void
    ) -> sgx_status_t;

    fn ec_ks_seal(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        some_string: *const c_char,
        len1: u32,
        text: *const c_char,
        len2: u32,
        strval: *mut c_void,
        len3: u32
    ) -> sgx_status_t;

    fn ec_ks_unseal(
        eid: sgx_enclave_id_t, 
        retval: *mut u32,
        user_pub_key: *const c_char,
        sealed: *const c_char,
        len3: u32
    ) -> sgx_status_t;

    fn ec_prove_me(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        code: u32,
        unsealed: *mut c_void
    ) -> sgx_status_t;

    fn ec_calc_sealed_size(
        eid: sgx_enclave_id_t, 
        retval: *mut u32,
        len1: u32
    ) -> sgx_status_t;

}

#[no_mangle]
pub extern "C"
fn oc_print(some_string: *const c_char) -> sgx_status_t {
    // let mut plaintext = vec![0; 1024];
    let c_str: &CStr = unsafe { CStr::from_ptr(some_string)};
    let plaintext = c_str.to_bytes();
    println!("{:?}", plaintext);
    return sgx_status_t::SGX_SUCCESS;    
}

fn init_enclave() -> SgxEnclave {
    error!("{}", "abc");
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
    text: String
}

#[derive(Deserialize)]
struct ExKeyReq {
    pubkey: String
}

#[derive(Deserialize)]
struct NotifyReq {
    pubkey: String,
    t: String,
    cond: String,
    h: String
}

#[derive(Deserialize)]
struct ProveReq {
    pubkey: String,
    t: String,
    cond: String,
    code: String
}

fn sendmail(account: &str, msg: &str) {
    println!("sending mail {} to {}", msg, account);
    let email = Message::builder()
        .from("Verification Node <verify@keysafe.network>".parse().unwrap())
        .reply_to("None <none@keysafe.network>".parse().unwrap())
        .to(format!("KS User<{}>", account).parse().unwrap())
        .subject("Confirmation Code")
        .body(String::from(msg))
        .unwrap();
    let creds = Credentials::new("verify@keysafe.network".to_string(), "".to_string());
    let mailer = SmtpTransport::relay("smtp.qiye.aliyun.com")
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

fn remove_previous_file(fname: &str) {
    let mut pat = String::new();
    pat.push_str(fname);
    pat.push_str(".*");
    for entry in glob(&pat).expect("Failed to find sealed file") {
        match entry {
            Ok(path) => {
                fs::remove_file(path).expect("Failed to remote file");
            },
            Err(e) => {
                info!("No previous file found {}", fname);
            }
        }
    }
}

fn save_file(fname: &str, val: Vec<u8>, n: usize) {
    println!("saving to file {}", fname);
    let file = File::create(fname);
    match file {
        Ok(mut f) => { 
            f.write_all(&val[0..n]);
            println!("successfully written to file");
        },
        Err(e) => println!("{}", e)
    } 
}

fn get_sealed(filename: &String) -> Vec<u8> {
    let content = fs::read(filename);
    match content {
        Ok(x) => x,
        _ => panic!("read file failed.")
    }
}

fn check_sealed(filename: &String) -> u32 {
    let mut pat = String::new();
    pat.push_str(filename);
    pat.push_str(".*");
    for entry in glob(&pat).expect("Failed to find sealed file") {
        match entry {
            Ok(path) => {
                info!("find file {}", filename);
                return path.extension().unwrap().to_str().unwrap().parse::<u32>().unwrap()
            },
            Err(e) => {
                info!("unable to find file {}", filename);
                return 0
            }
        }
    }
    return 0;
}

#[get("/health")]
async fn hello() -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Webapp is up and running!")
}

#[post("/exchange_key")]
async fn exchange_key(
    exKeyReq: web::Json<ExKeyReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut plaintext = vec![0; 1024];
    let mut plaintext2 = vec![0; 1024];
    println!("user pub key is {}", exKeyReq.pubkey);
    let result = unsafe {
        ec_ks_exchange(e.geteid(), &mut retval, 
            exKeyReq.pubkey.as_ptr() as *const c_char,
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void,
            plaintext2.as_mut_slice().as_mut_ptr() as * mut c_void,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => { 
            plaintext.resize(1024, 0);
            println!("sgx pub key {:?}", plaintext);
            println!("sgx share key {:?}", plaintext2);
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
    let e = &endex.enclave;
    let buffer = hex::decode(&sealReq.secret).expect("Decode Failed.");
    let mut len1 :u32 = 0;
    let result1 = unsafe {
        ec_calc_sealed_size(
            e.geteid(), &mut len1, u32::try_from(buffer.len()).unwrap())
    };

    match result1 {
        sgx_status_t::SGX_SUCCESS => {
        },
        _ => panic!("calc size failed.")
    };

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut plaintext = vec![0; usize::try_from(len1).unwrap()];
    let result = unsafe {
        println!("{:?}", buffer);
        println!("{:?}", sealReq.text);
        println!("len1 {}", u32::try_from(buffer.len()).unwrap());
        println!("len2 {}", u32::try_from(sealReq.text.len()).unwrap());
        println!("len3 {}", len1);
        ec_ks_seal(e.geteid(), &mut retval,
            buffer.as_ptr() as *const c_char, u32::try_from(buffer.len()).unwrap(),
            sealReq.text.as_ptr() as *const c_char, u32::try_from(sealReq.text.len()).unwrap(),
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void,
            len1
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            plaintext.resize(usize::try_from(len1).unwrap(), 0);
            let mut fname: String = sealReq.h.to_owned();
            let fsize = len1.to_string();
            fname.push_str(".");
            fname.push_str(&fsize);
            info!("saving file as {}", fname);
            remove_previous_file(&sealReq.h);
            save_file(&fname, plaintext, usize::try_from(len1).unwrap());
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

    let len3 = check_sealed(&notifyReq.h);
    info!("file extension is {}", len3.to_string());
    if len3 == 0 {
        return HttpResponse::Ok().body("seal not found");
    }

    let mut fname: String = notifyReq.h.to_owned();
    let fsize = len3.to_string();
    fname.push_str(".");
    fname.push_str(&fsize);
    info!("getting file {}", fname);
    let content = get_sealed(&fname);
    let mut len1 :u32 = 0;
    // get confirm code from enclave
    let result = unsafe {
        ec_ks_unseal(
            e.geteid(),
            &mut len1,
            notifyReq.pubkey.as_ptr() as *const c_char,
            content.as_ptr() as * const c_char,
            len3
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            if notifyReq.t.eq("email") {
                sendmail(&notifyReq.cond, &len1.to_string());
                HttpResponse::Ok().body("confirm code sent")
            } else if notifyReq.t.eq("mobile") {
                sendmsg(&notifyReq.cond, &len1.to_string());
                HttpResponse::Ok().body("confirm code sent")
            } else {
                HttpResponse::Ok().body(len1.to_string())
            }
        },
        _ => panic!("calling unseal failed.")
    }
}

#[post("/prove")]
async fn prove_user(
    proveReq: web::Json<ProveReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("proving {}", &proveReq.cond);
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut plaintext = vec![0; 8192];
    let result = unsafe {
        ec_prove_me(
            e.geteid(),
            &mut retval,
            proveReq.code.parse::<u32>().unwrap() ,
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            plaintext.resize(8192, 0);
            HttpResponse::Ok().body(plaintext)
        },
        _ => panic!("sgx prove me failed!")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    info!("logging!");
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
            .service(afs::Files::new("/", "./public").index_file("index.html"))
    })
    .bind_openssl("0.0.0.0:30000", builder)?
    .run()
    .await
}
