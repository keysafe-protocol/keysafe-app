extern crate openssl;
#[macro_use]
use std::str;
use std::cmp::*;
use std::time::SystemTime;
use serde_derive::{Deserialize, Serialize};
use actix_web::{
    get, post, web, Error, HttpRequest, HttpResponse, 
    Responder, FromRequest, http::header::HeaderValue, 
    http::header::TryIntoHeaderValue, http::header::InvalidHeaderValue};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;
use log::{error, info, warn};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use mysql::*;
use serde_json::{Value, Map};
use crate::ecall;
use crate::persistence;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rand::{thread_rng, Rng};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use web3::signing::{keccak256, recover};


pub struct AppState {
    pub enclave: SgxEnclave,
    pub db_pool: Pool,
    pub conf: HashMap<String, String>
}

pub struct UserState {
    pub state: Arc<Mutex<HashMap<String, String>>>
}

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // acount name
    exp: usize, // when to expire
}

struct AuthAccount {
    name: String,
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

#[post("/ks/exchange_key")]
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
    email: String
}
// with BaseResp

#[post("/ks/auth")]
pub async fn auth(
    auth_req: web::Json<AuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let result = gen_random();
    let sr = sendmail(&auth_req.email, &result.to_string(), &endex.conf);
    if sr == 0 {
        let mut states = user_state.state.lock().unwrap();
        states.insert(auth_req.email.clone(), result.to_string());
        HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
    } else {
        HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    }
}

#[derive(Deserialize)]
pub struct ConfirmReq {
    email: String,
    confirm_code: String
}

#[post("/ks/auth_confirm")]
pub async fn auth_confirm(
    confirm_req: web::Json<ConfirmReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let mut states = user_state.state.lock().unwrap();
    if let Some(v) = states.get(&confirm_req.email) {
        // when confirm code match, return a new token for current session
        if v == &confirm_req.confirm_code {
            states.remove(&confirm_req.email); 
            return HttpResponse::Ok().json(BaseResp{
                status: SUCC.to_string()
            });
        }
    }
    states.remove(&confirm_req.email); 
    HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    status: String,
    user: persistence::User
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    uname: String,
    email: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterUserReq {
    data: UserData,
    sig: String
}

#[post("/ks/register_user")]
pub async fn register_user(
    register_req: web::Json<RegisterUserReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let message = serde_json::to_string(&register_req.data).unwrap();
    let addr = verify_signed(&register_req.sig, &message);
    persistence::insert_user(
        &endex.db_pool, 
        persistence::User { kid: addr.clone(), 
            uname: register_req.data.uname.clone(),
            email: register_req.data.email.clone()});
    HttpResponse::Ok().json(BaseResp {status: SUCC.to_string()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DAuthPermitReq {
    data: persistence::DAuth,
    sig: String
}

#[post("/ks/dauth_permit")]
pub async fn dauth_permit(
    dauth_permit_req: web::Json<DAuthPermitReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let message = serde_json::to_string(&dauth_permit_req.data).unwrap();
    let addr = verify_signed(&dauth_permit_req.sig, &message);
    persistence::insert_dauth(
        &endex.db_pool, 
        persistence::DAuth { kid: addr.clone(), 
            dapp: dauth_permit_req.data.dapp.clone(),
            dapp_addr: dauth_permit_req.data.dapp_addr.clone(),
            apply_time: dauth_permit_req.data.apply_time.clone(),
            scope: dauth_permit_req.data.scope.clone(),
            da_status: dauth_permit_req.data.da_status
        });
    HttpResponse::Ok().json(BaseResp {status: SUCC.to_string()})
}

fn verify_signed(sig: &String, data: &String) -> String {
    println!("verify_signed");
    println!("signature is {}", sig);
    println!("data is {}", data);
    let sigdata = &sig[2..];
    let signature = hex::decode(sigdata).unwrap();
    let recoveryid = signature[64] as i32 - 27;
    let serialized = eth_message(data.to_string());
    let pubkey = recover(&serialized, &signature[..64], recoveryid).unwrap();
    let pubkey2 = format!("{:02X?}", pubkey);
    println!("pub key in hex is {}", pubkey2);
    return pubkey2;
}

pub fn eth_message(message: String) -> [u8; 32] {
    let msg = format!(
        "{}{}{}",
        "\x19Ethereum Signed Message:\n",
        message.len(),
        message
    );
    println!("msg is {}", msg);
    keccak256(msg.as_bytes(),
   )
}

#[post("/ks/user_info")]
pub async fn user_info(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>,
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let stmt = format!(
        "select * from user where kid = '{}'", 
        base_req.account
    );
    let users = persistence::query_user(&endex.db_pool, stmt);
    if users.is_empty() {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    HttpResponse::Ok().json(InfoResp {status: SUCC.to_string(), user: users[0].clone()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterOAuthReq {
    data: String,
    sig: String
}

#[post("/ks/register_github_oauth")]
pub async fn register_github_oauth(
    register_req: web::Json<RegisterOAuthReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let org = "github";
    let conf = &endex.conf;
    println!("oath request with code {}", &register_req.data);
    let client_id = conf.get("github_client_id").unwrap();
    let client_secret = conf.get("github_client_secret").unwrap();
    let oauth_result = github_oauth(client_id.clone(), 
        client_secret.clone(), register_req.data.clone());

    let addr = verify_signed(&register_req.sig, &register_req.data);

    persistence::insert_oauth(&endex.db_pool, 
        persistence::OAuth { kid: addr.clone(),
            org: "github".to_string(),
            oprofile: oauth_result.clone()
        });
    HttpResponse::Ok().json(BaseResp {status: SUCC.to_string()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteOAuthReq {
    account: String,
    org: String
}

#[post("/ks/delete_oauth")]
pub async fn delete_oauth(
    delete_oauth_req: web::Json<DeleteOAuthReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let conf = &endex.conf;
    persistence::delete_oauth(&endex.db_pool, 
        persistence::OAuth { kid: delete_oauth_req.account.to_string(),
            org: delete_oauth_req.org.to_string(),
            oprofile: "".to_string()
        });
    HttpResponse::Ok().json(BaseResp {status: SUCC.to_string()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoOAuthResp {
    status: String,
    oauth: Vec<persistence::OAuth>
}

#[post("/ks/oauth_info")]
pub async fn oauth_info(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let stmt = format!(
        "select * from oauth where kid = '{}'", 
        base_req.account
    );
    let oauths = persistence::query_oauth(&endex.db_pool, stmt);
    println!("{:?}", oauths);
    if oauths.is_empty() {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    HttpResponse::Ok().json(InfoOAuthResp {status: SUCC.to_string(), oauth: oauths})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoDAuthResp {
    status: String,
    dauth: Vec<persistence::DAuth>
}

#[post("/ks/dauth_info")]
pub async fn dauth_info(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let stmt = format!(
        "select * from dauth where kid = '{}'", 
        base_req.account
    );
    let dauths = persistence::query_dauth(&endex.db_pool, stmt);
    if dauths.is_empty() {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    HttpResponse::Ok().json(InfoDAuthResp {status: SUCC.to_string(), dauth: dauths})
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



#[derive(Deserialize, Serialize, Debug)]
pub struct GithubOAuthReq {
    client_id: String,
    client_secret: String,
    code: String
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GithubOAuthResp {
    access_token: String,
    scope: String,
    token_type: String
}

fn github_oauth2(
    client_id: String,
    client_secret: String,
    code: String
) -> String {
    "mock github oauth".to_string()
}

fn github_oauth(
    client_id: String,
    client_secret: String,
    code: String
) -> String {
    let http_client = reqwest::blocking::Client::new();
    let github_oauth_req = GithubOAuthReq {
        client_id: client_id,
        client_secret: client_secret,
        code: code
    };
    let res = http_client.post("https://github.com/login/oauth/access_token")
        .json(&github_oauth_req)
        .header("Accept", "application/json")
        .header("User-Agent", "keysafe-protocol")
        .send().unwrap().json::<GithubOAuthResp>().unwrap();
    println!("access token response is {:?}", res);
    // println!("github get access token {}", &res.access_token);
    let access_token = res.access_token;
    // let access_token = "123";
    return http_client.post("https://api.github.com/user")
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "keysafe-protocol")
        .send().unwrap().text().unwrap();
}

fn parse_oauth_profile(oauth_result: String) -> String {
    let parsed: Value = serde_json::from_str(&oauth_result).unwrap(); 
    let obj: Map<String, Value> = parsed.as_object().unwrap().clone();
    println!("access obj {:?}", obj);
    let email: String = obj.clone().get("email").unwrap().as_str().unwrap().to_string();
    email
}

fn sendmail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    if conf.get("env").unwrap() == "dev" {
        println!("send mail {} to {}", msg, account);
        return 0;
    }
    if conf.contains_key("proxy_mail") {
        return proxy_mail(account, msg, conf);
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
        Ok(_) => { println!("Email sent successfully!"); return 0 },
        Err(e) => { println!("Could not send email: {:?}", e); return 1 },
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyMailReq {
    account: String,
    msg: String
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyMailResp {
    status: String
}

fn proxy_mail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    println!("calling proxy mail {} {}", account, msg);
    let proxy_mail_server = conf.get("proxy_mail_server").unwrap();
    let client =  reqwest::blocking::Client::new();
    let proxy_mail_req = ProxyMailReq {
        account: account.to_owned(),
        msg: msg.to_owned()
    };
    let res = client.post(proxy_mail_server)
        .json(&proxy_mail_req)
        .send().unwrap().json::<ProxyMailResp>().unwrap();
    if res.status == SUCC {
        return 0;
    }
    return 1;
}

fn system_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

pub fn verify_token(token_option: Option<&HeaderValue>, secret: &str) -> bool {
    if let Some(v) = token_option {
        println!("analysing header {}", v.to_str().unwrap());
        println!("decode with secret {}", secret);
        let mut validation = Validation::new(Algorithm::HS256);
        let token = v.to_str().unwrap();
        let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &validation);
        match token_data {
            Ok(c) => true,
            _ => {
                println!("token verify failed");
                false 
            }
        }
    } else {
        println!("extract token from header failed");
        false
    }
}

#[get("/health")]
pub async fn hello(endex: web::Data<AppState>) -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Webapp is up and running!")
}
