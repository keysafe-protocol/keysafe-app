extern crate openssl;
#[macro_use]
use std::str;
use std::time::SystemTime;
use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, HttpResponse, Responder};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;
use log::{error, info, warn};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use mysql::*;
use crate::ecall;
use crate::persistence;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rand::{thread_rng, Rng};

pub struct AppState {
    pub enclave: SgxEnclave,
    pub db_pool: Pool,
    pub conf: HashMap<String, String>
}

pub struct UserState {
    pub state: Arc<Mutex<HashMap<String, String>>>
}

#[derive(Deserialize)]
pub struct BaseReq {
    account: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaseResp {
    status: String,
}

#[derive(Deserialize)]
pub struct ExchangeKeyReq {
    key: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeKeyResp {
    status: String,
    key: Vec<c_char>
}

fn gen_random() -> i32 {
    let mut rng = thread_rng();
    rng.gen_range(1000..9999)
}

static SUCC: &'static str = "success";
static FAIL: &'static str = "fail";

#[post("/exchange_key")]
pub async fn exchange_key(
    ex_key_req: web::Json<ExchangeKeyReq>,
    endex: web::Data<AppState>
) ->  impl Responder {
    let e = &endex.enclave;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let mut out_key: Vec<u8> = vec![0; 256];
    let mut plaintext2 = vec![0; 256];
    println!("user pub key is {}", ex_key_req.key);
    let result = unsafe {
        ecall::ec_ks_exchange(e.geteid(), 
            &mut sgx_result, 
            ex_key_req.key.as_ptr() as *const c_char,
            out_key.as_mut_slice().as_mut_ptr() as * mut c_char,
            plaintext2.as_mut_slice().as_mut_ptr() as * mut c_char,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => { 
            out_key.resize(256, 0);
            let mut chars: Vec<char>= Vec::new();
            for i in out_key {
                if i != 0 {
                    chars.push(i as char);
                }
            }
            let hex_key: String = chars.into_iter().collect();
            println!("sgx pub key {}", hex_key);
            HttpResponse::Ok().body(hex_key)
        },
        _ => panic!("exchang key failed.")
    }
}

#[derive(Deserialize)]
pub struct AuthReq {
    account: String,
    key: String,
}
// with BaseResp

#[post("/auth")]
pub async fn auth(
    auth_req: web::Json<AuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let result = gen_random();
    sendmail(&auth_req.account, &result.to_string(), &endex.conf);
    let mut states = user_state.state.lock().unwrap();
    states.insert(auth_req.account.clone(), result.to_string());
    HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
}

#[derive(Deserialize)]
pub struct ConfirmReq {
    account: String,
    mail: String,
    cipher_code: String
}
// with BaseResp

#[post("/auth_confirm")]
pub async fn auth_confirm(
    confirm_req: web::Json<ConfirmReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut states = user_state.state.lock().unwrap();
    match states.get(&confirm_req.account) {
        Some(v) => {
            if v == &confirm_req.cipher_code {
                HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
            } else {
                states.remove(&confirm_req.account); 
                HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
            }
        },
        None => { 
            states.remove(&confirm_req.account); 
            HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    status: String,
    data: Vec<Coin>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Coin {
    owner: String,
    chain: String,
    chain_addr: String
}
//with BaseReq

#[post("/info")]
pub async fn info(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let stmt = format!(
        "select * from user_secret where kid = '{}'", 
        base_req.account
    );
    let secrets = persistence::query_user_secret(&endex.db_pool, stmt);
    let dstmt = format!(
        "select * from user_secret where delegate_id = '{}'", 
        base_req.account
    );
    let dsecrets = persistence::query_user_secret(&endex.db_pool, dstmt);
    let mut v = Vec::new();
    for i in secrets {
        if i.kid == base_req.account {
            v.push(Coin {
                owner: base_req.account.clone(),
                chain: i.chain.clone(), 
                chain_addr: i.chain_addr.clone()
            });
        }
    }
    for i in &dsecrets {
        if i.delegate_id == base_req.account {
            v.push(Coin {
                owner: i.kid.clone(),
                chain: i.chain.clone(), 
                chain_addr: i.chain_addr.clone()
            });
        }
    }
    HttpResponse::Ok().json(InfoResp {status: SUCC.to_string(), data: v})
}

#[derive(Deserialize)]
pub struct RegisterMailAuthReq {
    account: String,
    cipher_mail: String,
    mail: String
}

#[post("/register_mail_auth")]
pub async fn register_mail_auth(
    reg_mail_auth_req: web::Json<RegisterMailAuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut states = user_state.state.lock().unwrap();
    if states.contains_key(&reg_mail_auth_req.account) {
        let result = gen_random();
        states.insert(reg_mail_auth_req.account.clone(), result.to_string());
        sendmail(&reg_mail_auth_req.mail, &result.to_string(), &endex.conf);
        HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})    
    } else {
        HttpResponse::Ok().json(BaseResp {status: FAIL.to_string()})
    }
}

#[derive(Deserialize)]
pub struct RegisterMailReq {
    account: String,
    mail: String,
    cipher_code: String
}

fn calc_tee_size(e: sgx_enclave_id_t, hex_str: &String) -> usize {
    let mut size: u32 = 0;
    let bcode = hex::decode(&hex_str).expect("Decode Failed.");
    let result = unsafe {
        ecall::ec_calc_sealed_size(
            e,
            &mut size,
            u32::try_from(bcode.len()).unwrap()
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            size.try_into().unwrap()
        },
        _ => 0
    }
}

// register mail use ConfirmReq and BaseResp
#[post("/register_mail")]
pub async fn register_mail(
    register_mail_req: web::Json<RegisterMailReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut states = user_state.state.lock().unwrap();
    match states.get(&register_mail_req.account) {
        Some(v) => {
            if v == &register_mail_req.cipher_code {
                persistence::insert_user_cond(
                    &endex.db_pool, 
                    persistence::UserCond {
                        kid: register_mail_req.account.clone(),
                        cond_type: "email".to_string(),
                        tee_cond_value: register_mail_req.mail.clone(),
                        tee_cond_size: 256    
                    }
                );
                HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
            } else {
                HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
            }
        },
        None => { 
            HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    }
}


#[derive(Deserialize)]
pub struct RegPasswordReq {
    account: String,
    cipher_code: String
}

#[post("/register_password")]
pub async fn register_password(
    register_password_req: web::Json<RegPasswordReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut states = user_state.state.lock().unwrap();
    match states.get(&register_password_req.account) {
        Some(v) => {
            persistence::insert_user_cond(
                &endex.db_pool, 
                persistence::UserCond {
                    kid: register_password_req.account.clone(),
                    cond_type: "password".to_string(),
                    tee_cond_value: register_password_req.cipher_code.clone(),
                    tee_cond_size: 256    
                }
            );
            HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
        },
        None => { 
            HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterGauthResp {
    status: String,
    gauth: String,
}

#[post("/register_gauth")]
pub async fn register_gauth(
    register_gauth_req: web::Json<BaseReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut states = user_state.state.lock().unwrap();
    match states.get(&register_gauth_req.account) {
        Some(v) => {
            HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
        },
        None => { 
            HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    }
}

#[derive(Deserialize)]
pub struct DelegateReq {
    account: String,
    chain: String,
    chain_addr: String,
    to: String
}

#[post("/delegate")]
pub async fn delegate(
    delegate_req: web::Json<DelegateReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    println!("delegating account {} to {}", delegate_req.account, delegate_req.to);
    let a = persistence::update_delegate(
        &endex.db_pool,
        &delegate_req.to,
        &delegate_req.account,
        &delegate_req.chain,
        &delegate_req.chain_addr
    );
    HttpResponse::Ok().json(BaseResp {status: SUCC.to_string()})
}

#[derive(Deserialize)]
pub struct SealReq {
    account: String,
    cond_type: String,
    chain: String,
    chain_addr: String,
    cipher_secret: String
}

#[post("/seal")]
pub async fn seal(
    seal_req: web::Json<SealReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut states = user_state.state.lock().unwrap();
    match states.get(&seal_req.account) {
        Some(v) => {
            persistence::insert_user_secret(
                &endex.db_pool, 
                persistence::UserSecret {
                    kid: seal_req.account.clone(),
                    cond_type: seal_req.cond_type.clone(),
                    chain: seal_req.chain.clone(),
                    chain_addr: seal_req.chain_addr.clone(),
                    tee_secret: seal_req.cipher_secret.clone(),
                    tee_secret_size: 256,
                    delegate_id: "".to_string()
                }
            );
            HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
        },
        None => { 
            HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    }
}

#[derive(Deserialize)]
pub struct UnsealReq {
    account: String,
    cond_type: String,
    chain: String,
    chain_addr: String,
    cipher_cond_value: String,
    owner: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResp {
    status: String,
    cipher_secret: String
}

#[post("/unseal")]
pub async fn unseal(
    unseal_req: web::Json<UnsealReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    // get condition value from db sealed
    let mut states = user_state.state.lock().unwrap();
    if !states.contains_key(&unseal_req.account) {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    // get condition
    let cond_stmt = format!(
        "select * from user_cond where kid='{}' and cond_type='{}'",
        unseal_req.account, unseal_req.cond_type
    );
    let uconds = persistence::query_user_cond(
        &endex.db_pool, cond_stmt 
    );
    if uconds.is_empty() {
        println!("not found any user {} cond {}.", &unseal_req.account, &unseal_req.cond_type);
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }

    // verify condition, if fail, return 
    let cond_value = uconds[0].tee_cond_value.clone();

    if &unseal_req.cond_type == "email" {
        match states.get(&unseal_req.account) {
            Some(v) => {
                if v != &unseal_req.cipher_cond_value {
                    return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
                }
            },
            None => { 
                return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
            }
        }
    } else if &unseal_req.cond_type == "password" {
        if unseal_req.cipher_cond_value != cond_value {
            return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    } else if &unseal_req.cond_type == "gauth" {
    }
    // return sealed secret when pass verify
    let secret_stmt = format!(
        "select * from user_secret where kid='{}' and chain='{}' and chain_addr='{}' and cond_type='{}'",
        unseal_req.owner, unseal_req.chain, unseal_req.chain_addr, unseal_req.cond_type
    );
    let usecrets = persistence::query_user_secret(
        &endex.db_pool, secret_stmt);
    if usecrets.is_empty() {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let secret_value = usecrets[0].tee_secret.clone();
    HttpResponse::Ok().json(UnsealResp{
        status: SUCC.to_string(),
        cipher_secret: secret_value
    })
}  

fn sendmail(account: &str, msg: &str, conf: &HashMap<String, String>) {
    if conf.get("env").unwrap() == "dev" {
        println!("send mail {} to {}", msg, account);
        return;
    }
    println!("send mail {} to {}", msg, account);
    let email = Message::builder()
        .from("Verification Node <verify@keysafe.network>".parse().unwrap())
        .reply_to("None <none@keysafe.network>".parse().unwrap())
        .to(format!("KS User<{}>", account).parse().unwrap())
        .subject("Confirmation Code")
        .body(String::from(msg))
        .unwrap();
    let email_account = conf.get("email_account").unwrap();
    let email_password = conf.get("email_password").unwrap();
    let email_server = conf.get("email_server").unwrap();
    let creds = Credentials::new(email_account.to_owned(), email_password.to_owned());
    let mailer = SmtpTransport::relay(email_server)
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {:?}", e),
    }
}

fn system_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

#[get("/health")]
pub async fn hello(endex: web::Data<AppState>) -> impl Responder {
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
            persistence::write_file(&fname, plaintext1, len1.try_into().unwrap());
            // println!("getting encrypted gauth secret {}", len2.to_string());
            let hexResponse = hex::encode(&plaintext2[0..len2.try_into().unwrap()]);
            HttpResponse::Ok().body(hexResponse)
        },
        _ => panic!("require GAuth secret failed!")
    }
}

#[post("/notify")]
pub async fn notify_user(
    notifyReq: web::Json<NotifyReq>,
    endex: web::Data<AppState>
) -> impl Responder {
    println!("unsealing notifying {}", &notifyReq.cond);
    let e = &endex.enclave;

    let len3 = persistence::check_sealed(&notifyReq.h);
    println!("unsealing file extension is {}", len3.to_string());
    if len3 == 0 {
        return HttpResponse::Ok().body("seal not found");
    }

    let mut fname: String = notifyReq.h.to_owned();
    let fsize = len3.to_string();
    fname.push_str(".");
    fname.push_str(&fsize);
    println!("unsealing getting file {}", fname);
    let content = persistence::read_file(&fname);
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
                sendmail(&notifyReq.cond, &return_val.to_string(), &endex.conf);
                HttpResponse::Ok().body("confirm code sent")
            } else if notifyReq.t.eq("mobile") {
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
    let secret = persistence::read_file(&format!("{}_secret", fname));
    let sealed_len = persistence::check_sealed(&fname);
    let fname2 = &proveReq.h;
    let sealed = persistence::read_file(&format!("{}.{}", fname2, sealed_len.to_string()));
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
