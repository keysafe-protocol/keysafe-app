extern crate openssl;
#[macro_use]

use std::fs::File;
use std::fs;
use std::str;
use std::time::SystemTime;

use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;

use log::{error, info, warn};
use glob::glob;

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use std::io::Write;

use crate::ecall;
use sgx_urts::SgxEnclave;

#[derive(Deserialize)]
pub struct SealReq {
    pubkey: String,
    h: String,
    secret: String,
    text: String
}

#[derive(Deserialize)]
pub struct ExKeyReq {
    pubkey: String
}

#[derive(Deserialize)]
pub struct NotifyReq {
    pubkey: String,
    t: String,
    cond: String,
    h: String
}

#[derive(Deserialize)]
pub struct ProveReq {
    pubkey: String,
    t: String,
    h: String,
    code: String
}

#[derive(Deserialize)]
pub struct RequireSecretReq {
    pubkey: String,
    h: String,
    email: String
}


pub struct AppState {
    pub enclave: SgxEnclave
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
                println!("No previous file found {}", fname);
            }
        }
    }
}

fn write_file(fname: &str, val: Vec<u8>, n: usize) {
    println!("sealing: saving to file {}", fname);
    let file = File::create(fname);
    match file {
        Ok(mut f) => { 
            f.write_all(&val[0..n]);
            println!("successfully written to file");
        },
        Err(e) => println!("{}", e)
    } 
}

fn read_file(filename: &String) -> Vec<u8> {
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
                println!("find file {}", filename);
                return path.extension().unwrap().to_str().unwrap().parse::<u32>().unwrap()
            },
            Err(e) => {
                println!("unable to find file {}", filename);
                return 0
            }
        }
    }
    return 0;
}

fn system_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

#[get("/health")]
pub async fn hello() -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Webapp is up and running!")
}

#[post("/require_secret")]
pub async fn require_secret(
    requireSecret: web::Json<RequireSecretReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let len1: u32 = 770;
    let len2: u32 = 256;
    let mut plaintext1 = vec![0; len1.try_into().unwrap()];
    let mut plaintext2 = vec![0; len2.try_into().unwrap()];
    println!("calling gen gauth secret");
    let result = unsafe {
        ecall::ec_gen_gauth_secret(
            e.geteid(), 
            &mut retval,
            plaintext1.as_mut_slice().as_mut_ptr() as * mut c_void,
            len1,
            plaintext2.as_mut_slice().as_mut_ptr() as * mut c_void
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("calling gen gauth success.");
            plaintext1.resize(len1.try_into().unwrap(), 0);
            plaintext2.resize(len2.try_into().unwrap(), 0);
            let mut fname: String = requireSecret.h.to_owned();
            fname.push_str("_secret");
            println!("sealing gauth secret {:?}", plaintext1);
            println!("gauth secret length {}", len1.to_string());
            write_file(&fname, plaintext1, len1.try_into().unwrap());
            // println!("getting encrypted gauth secret {}", len2.to_string());
            let hexResponse = hex::encode(&plaintext2[0..len2.try_into().unwrap()]);
            HttpResponse::Ok().body(hexResponse)
        },
        _ => panic!("require GAuth secret failed!")
    }
}

#[post("/exchange_key")]
pub async fn exchange_key(
    exKeyReq: web::Json<ExKeyReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut plaintext = vec![0; 1024];
    let mut plaintext2 = vec![0; 1024];
    println!("user pub key is {}", exKeyReq.pubkey);
    let result = unsafe {
        ecall::ec_ks_exchange(e.geteid(), &mut retval, 
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
pub async fn seal(
    sealReq: web::Json<SealReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    let e = &endex.enclave;
    let buffer = hex::decode(&sealReq.secret).expect("Decode Failed.");
    let mut len1 :u32 = 0;
    let result1 = unsafe {
        ecall::ec_calc_sealed_size(
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
        println!("sealing encrypted: {:?}", buffer);
        println!("sealing encrypted length: {}", u32::try_from(buffer.len()).unwrap());
        println!("sealing raw text: {:?}", sealReq.text);
        println!("sealing text length: {}", u32::try_from(sealReq.text.len()).unwrap());
        println!("sealing size: {}", len1);
        ecall::ec_ks_seal(e.geteid(), &mut retval,
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
            println!("sealing sealed file content {:?}", plaintext);
            println!("sealing saving file as {}", fname);
            remove_previous_file(&sealReq.h);
            write_file(&fname, plaintext, usize::try_from(len1).unwrap());
            HttpResponse::Ok().body("Seal Completed.")
        },
        _ => panic!("Seal failed!")
    }
}

#[post("/notify")]
pub async fn notify_user(
    notifyReq: web::Json<NotifyReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("unsealing notifying {}", &notifyReq.cond);
    let e = &endex.enclave;

    let len3 = check_sealed(&notifyReq.h);
    println!("unsealing file extension is {}", len3.to_string());
    if len3 == 0 {
        return HttpResponse::Ok().body("seal not found");
    }

    let mut fname: String = notifyReq.h.to_owned();
    let fsize = len3.to_string();
    fname.push_str(".");
    fname.push_str(&fsize);
    println!("unsealing getting file {}", fname);
    let content = read_file(&fname);
    println!("unsealing file content {:?}", content);
    println!("unsealing file length: {:?}", content.len());
    let mut return_val :u32 = 0;
    // get confirm code from enclave
    let result = unsafe {
        ecall::ec_ks_unseal(
            e.geteid(),
            &mut return_val,
            notifyReq.pubkey.as_ptr() as *const c_char,
            content.as_ptr() as * const c_char,
            len3
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            if notifyReq.t.eq("email") {
                sendmail(&notifyReq.cond, &return_val.to_string());
                HttpResponse::Ok().body("confirm code sent")
            } else if notifyReq.t.eq("mobile") {
                sendmsg(&notifyReq.cond, &return_val.to_string());
                HttpResponse::Ok().body("confirm code sent")
            } else {
                HttpResponse::Ok().body(return_val.to_string())
            }
        },
        _ => panic!("calling unseal failed.")
    }
}

#[post("/prove_code")]
pub async fn prove_code(
    proveReq: web::Json<ProveReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("proving code for {}", &proveReq.t);
    let e = &endex.enclave;
    let mut plaintext = vec![0; 8192];
    let code = hex::decode(&proveReq.code).expect("Decode Failed.");
    let fname = &proveReq.h;
    let secret = read_file(&format!("{}_secret", fname));
    let sealed_len = check_sealed(&fname);
    let fname2 = &proveReq.h;
    let sealed = read_file(&format!("{}.{}", fname2, sealed_len.to_string()));
    let mut retval :u32 = 0;
    println!("encrypted code {:?}", sealed);
    let result = unsafe {
        ecall::ec_check_code(
            e.geteid(),
            &mut retval,
            secret.as_ptr() as * const c_char,
            secret.len().try_into().unwrap(),
            system_time(),
            code.as_ptr() as * const c_char,
            code.len().try_into().unwrap(),
            sealed.as_ptr() as * const c_char,
            sealed_len,
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            plaintext.resize(8192, 0);
            let hexResponse = hex::encode(&plaintext[0..usize::try_from(retval).unwrap()]);
            println!("proving get sealed data as hex {}", hexResponse);
            HttpResponse::Ok().body(hexResponse)
        },
        _ => panic!("sgx prove me failed!")
    }    
}

#[post("/prove")]
pub async fn prove_user(
    proveReq: web::Json<ProveReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("proving {}", &proveReq.pubkey);
    let e = &endex.enclave;
    let mut plaintext = vec![0; 8192];
    let buffer = hex::decode(&proveReq.code).expect("Decode Failed.");
    let mut retval :u32 = 0;
    println!("encrypted code {:?}", buffer);
    let result = unsafe {
        ecall::ec_prove_me(
            e.geteid(),
            &mut retval,
            buffer.as_ptr() as *const c_char,
            u32::try_from(buffer.len()).unwrap(),
            plaintext.as_mut_slice().as_mut_ptr() as * mut c_void
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            plaintext.resize(8192, 0);
            let hexResponse = hex::encode(&plaintext[0..usize::try_from(retval).unwrap()]);
            println!("proving get sealed data as hex {}", hexResponse);
            HttpResponse::Ok().body(hexResponse)
        },
        _ => panic!("sgx prove me failed!")
    }
}