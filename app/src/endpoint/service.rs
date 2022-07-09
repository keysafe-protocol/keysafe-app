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
    account: String,
    key: String,
}
// with BaseResp


#[post("/ks/auth")]
pub async fn auth(
    auth_req: web::Json<AuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let result = gen_random();
    let sr = sendmail(&auth_req.account, &result.to_string(), &endex.conf);
    if sr == 0 {
        let mut states = user_state.state.lock().unwrap();
        states.insert(auth_req.account.clone(), result.to_string());
        HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
    } else {
        HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    }
}

#[derive(Deserialize)]
pub struct ConfirmReq {
    account: String,
    mail: String,
    cipher_code: String
}
// with BaseResp

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmResp {
    status: String,
    token: String
}

#[post("/ks/auth_confirm")]
pub async fn auth_confirm(
    confirm_req: web::Json<ConfirmReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let mut states = user_state.state.lock().unwrap();
    if let Some(v) = states.get(&confirm_req.account) {
        // when confirm code match, return a new token for current session
        if v == &confirm_req.cipher_code {
            println!("generating token with secret {}", &endex.conf["secret"]);
            return HttpResponse::Ok().json(ConfirmResp{
                status: SUCC.to_string(),
                token: encode(
                    &Header::default(), 
                    &Claims{
                        sub: confirm_req.account.clone(),
                        exp: (system_time() + 7 * 24 * 3600).try_into().unwrap()
                    },
                    &EncodingKey::from_secret(&endex.conf["secret"].as_bytes()),
                ).unwrap()
            });
        } 
    }       
    states.remove(&confirm_req.account); 
    HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    status: String,
    data: Vec<Coin>
}

#[derive(Debug, Serialize, Deserialize, Eq)]
pub struct Coin {
    owner: String,
    chain: String,
    chain_addr: String
}
//with BaseReq
impl Ord for Coin {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.owner, &self.chain, &self.chain_addr)
        .cmp(&(&other.owner, &other.chain, &other.chain_addr))
    }
}

impl PartialOrd for Coin {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Coin {
    fn eq(&self, other: &Self) -> bool {
        (&self.owner, &self.chain, &self.chain_addr) == (&other.owner, &other.chain, &other.chain_addr)
    }
}

#[post("/ks/info")]
pub async fn info(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>,
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let mut v = Vec::new();
    let stmt = format!(
        "select * from user_secret where kid = '{}'", 
        base_req.account
    );
    let secrets = persistence::query_user_secret(&endex.db_pool, stmt);
    for i in &secrets {
        v.push(Coin {
            owner: base_req.account.clone(),
            chain: i.chain.clone(), 
            chain_addr: i.chain_addr.clone()
        });
    }

    let dstmt = format!(
        "select * from user_secret where delegate_id = '{}'", 
        base_req.account
    );
    let dsecrets = persistence::query_user_secret(&endex.db_pool, dstmt);
    for i in &dsecrets {
        v.push(Coin {
            owner: i.kid.clone(),
            chain: i.chain.clone(), 
            chain_addr: i.chain_addr.clone()
        });
    }

    v.sort();
    v.dedup();
    HttpResponse::Ok().json(InfoResp {status: SUCC.to_string(), data: v})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoMailResp {
    status: String,
    data: String
}

#[post("/ks/info_mail")]
pub async fn info_mail(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>,
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let stmt = format!(
        "select * from user_cond where kid = '{}' and cond_type ='email'", 
        base_req.account
    );
    let user_conds = persistence::query_user_cond(&endex.db_pool, stmt);
    if user_conds.is_empty() {
        return HttpResponse::Ok().json(
            InfoMailResp{
                status: FAIL.to_string(), data: "".to_string()});
    }
    let mail = user_conds[0].tee_cond_value.clone();
    HttpResponse::Ok().json(InfoMailResp {status: SUCC.to_string(), data: mail})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoOAuthResp {
    status: String,
    data: Vec<persistence::UserOAuth>
}

#[post("/ks/info_oauth")]
pub async fn info_oauth(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    // to prevent sql injection 
    if base_req.account.contains("'") {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let stmt = format!(
        "select * from user_oauth where kid = '{}'", 
        base_req.account
    );
    let oauths = persistence::query_user_oauth2(&endex.db_pool, &endex.conf, stmt);
    println!("{:?}", oauths);
    HttpResponse::Ok().json(InfoOAuthResp {status: SUCC.to_string(), data: oauths})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Web3CondResp {
    status: String,
    data: Vec<String>
}

#[post("/ks/web3/cond")]
pub async fn web3_cond(
    base_req: web::Json<BaseReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let query_stmt = format!("select * from user_cond where kid = '{}'", base_req.account);
    let user_conds = persistence::query_user_cond(&endex.db_pool, query_stmt);
    let mut v = Vec::new();
    for i in &user_conds {
        v.push(i.cond_type.clone());
    }
    HttpResponse::Ok().json(Web3CondResp {status: SUCC.to_string(), data: v})
}


#[derive(Deserialize)]
pub struct RegisterMailAuthReq {
    account: String,
    cipher_mail: String,
    mail: String
}

#[post("/ks/register_mail_auth")]
pub async fn register_mail_auth(
    reg_mail_auth_req: web::Json<RegisterMailAuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let mut states = user_state.state.lock().unwrap();
    let result = gen_random();
    states.insert(reg_mail_auth_req.account.clone(), result.to_string());
    let sr = sendmail(&reg_mail_auth_req.mail, &result.to_string(), &endex.conf);
    if sr == 0 {
        return HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()});    
    } 
    HttpResponse::Ok().json(BaseResp {status: FAIL.to_string()})
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
#[post("/ks/register_mail")]
pub async fn register_mail(
    register_mail_req: web::Json<RegisterMailReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let mut states = user_state.state.lock().unwrap();
    if let Some(v) = states.get(&register_mail_req.account) {
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
            return HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()});
        } 
    }   
    HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
}

#[derive(Deserialize)]
pub struct RegPasswordReq {
    account: String,
    cipher_code: String
}

#[post("/ks/register_password")]
pub async fn register_password(
    register_password_req: web::Json<RegPasswordReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
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
}

#[post("/ks/register_oauth_github")]
pub async fn register_oauth_github(
    register_oauth_req: web::Json<OAuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let conf = &endex.conf;
    let client_id = conf.get("github_client_id").unwrap();
    let client_secret = conf.get("github_client_secret").unwrap();
    let oauth_result = github_oauth(
        client_id.clone(), client_secret.clone(), register_oauth_req.code.clone());
    let email = parse_oauth_profile(oauth_result.clone());
    persistence::insert_user_cond(
        &endex.db_pool, 
        persistence::UserCond {
            kid: register_oauth_req.account.clone(),
            cond_type: "oauth@github".to_string(),
            tee_cond_value: email,
            tee_cond_size: 256    
        }
    );
    return HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()});
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterGauthResp {
    status: String,
    gauth: String,
}

#[post("/ks/register_gauth")]
pub async fn register_gauth(
    register_gauth_req: web::Json<BaseReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let sealed_size: u32 = 770;
    let cipher_size: u32 = 256;
    let mut sealed_gauth = vec![0; sealed_size.try_into().unwrap()];
    let mut cipher_gauth: Vec<u8> = vec![0; cipher_size.try_into().unwrap()];
    println!("calling gen gauth secret");
    let result = unsafe {
        ecall::ec_gen_gauth_secret(
            e.geteid(), 
            &mut retval,
            sealed_gauth.as_mut_slice().as_mut_ptr() as * mut c_char,
            sealed_size,
            cipher_gauth.as_mut_slice().as_mut_ptr() as * mut c_char
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("calling gen gauth success.");
            println!("sealed_gauth {:?}", sealed_gauth);
            println!("cipher_gauth {:?}", cipher_gauth);
            sealed_gauth.resize(sealed_size.try_into().unwrap(), 0);
            cipher_gauth.resize(cipher_size.try_into().unwrap(), 0);
            let mut chars: Vec<char>= Vec::new();
            for i in cipher_gauth {
                if i != 0 {
                    chars.push(i as char);
                }
            }
            let hex_cipher: String = chars.into_iter().collect();
            println!("cipher hex {:?}", hex_cipher);
            //let hex_sealed = hex::encode(&sealed_gauth[0..sealed_size.try_into().unwrap()]);
            // let hex_cipher = hex::encode(&cipher_gauth[0..cipher_size.try_into().unwrap()]);
            persistence::insert_user_cond(
                &endex.db_pool,
                persistence::UserCond {
                    kid: register_gauth_req.account.clone(),
                    cond_type: "gauth".to_string(),
                    tee_cond_value: hex_cipher[0..26].to_string(),
                    tee_cond_size: 256
                }
            );
            // println!("getting encrypted gauth secret {}", len2.to_string());
            HttpResponse::Ok().json(RegisterGauthResp{status: SUCC.to_string(), gauth: hex_cipher})
        },
        _ => panic!("require GAuth secret failed!")
    }
}

#[derive(Deserialize)]
pub struct DelegateReq {
    account: String,
    to: String
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateResp {
    status: String,
    error_msg: String
}

#[post("/ks/delegate")]
pub async fn delegate(
    delegate_req: web::Json<DelegateReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let query_stmt = format!("select * from user_cond where kid = '{}'", delegate_req.to);
    let query_result = persistence::query_user_cond(&endex.db_pool, query_stmt);
    if query_result.is_empty() {
        return HttpResponse::Ok().json(
            DelegateResp{status: FAIL.to_string(), error_msg:"delegate account doesn't exists".to_string() });
    }
    println!("delegating account {} to {}", delegate_req.account, delegate_req.to);
    let a = persistence::update_delegate(
        &endex.db_pool,
        &delegate_req.to,
        &delegate_req.account
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

#[post("/ks/seal")]
pub async fn seal(
    seal_req: web::Json<SealReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
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
}


#[derive(Deserialize)]
pub struct DeleteSealReq {
    account: String,
    chain: String,
    chain_addr: String,
}

#[post("/ks/delete_seal")]
pub async fn delete_seal(
    delete_req: web::Json<DeleteSealReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    //TODO: add account verify again header
    persistence::delete_user_secret(&endex.db_pool, persistence::UserSecret{
        kid: delete_req.account.clone(),
        chain: delete_req.chain.clone(),
        chain_addr: delete_req.chain_addr.clone(),
        cond_type: "".to_string(),
        tee_secret: "".to_string(),
        tee_secret_size: 0,
        delegate_id: "".to_string()
    });
    HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
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

#[post("/ks/unseal")]
pub async fn unseal(
    unseal_req: web::Json<UnsealReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let conf = &endex.conf;
    let systime = system_time();
    // get condition value from db sealed

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
        let mut states = user_state.state.lock().unwrap();
        if let Some(v) = states.get(&unseal_req.account) {
            if v != &unseal_req.cipher_cond_value {
                println!("cipher code does not match");
                return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
            }
        } else {
            println!("state does not contain user account");
            return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    } else if &unseal_req.cond_type == "password" {
        if unseal_req.cipher_cond_value != cond_value {
            return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    } else if &unseal_req.cond_type == "gauth" {
        //let sealed_gauth = hex::decode(cond_value).expect("Decode failed.");
        let mut sgx_result = sgx_status_t::SGX_SUCCESS;
        println!("gauth {} with code {}", cond_value, unseal_req.cipher_cond_value.parse::<i32>().unwrap());
        let result = unsafe {
            ecall::ec_verify_gauth_code(
                e.geteid(),
                &mut sgx_result,
                unseal_req.cipher_cond_value.parse::<i32>().unwrap(),
                cond_value.as_ptr() as * const c_char,
                systime
            )
        };
        println!("sgx result return {}", result);
        println!("sgx result in arg {}", sgx_result);
        match sgx_result {
            sgx_status_t::SGX_SUCCESS => {},
            _ => return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
    } else if &unseal_req.cond_type == "oauth@github" {
        let client_id = conf.get("github_client_id").unwrap();
        let client_secret = conf.get("github_client_secret").unwrap();
        let oauth_result = github_oauth(
            client_id.clone(), client_secret.clone(), unseal_req.cipher_cond_value.clone());
        let email = parse_oauth_profile(oauth_result.clone());
        if email != cond_value {
            println!("email {}", email);
            println!("cond value {}", cond_value);
            return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
        }
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

#[derive(Deserialize, Debug)]
pub struct OAuthReq {
    account: String,
    org: String,
    code: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthResp {
    profile: String
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

#[post("/ks/oauth")]
pub async fn oauth(
    oauth_req: web::Json<OAuthReq>,
    endex: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let conf = &endex.conf;
    println!("oath request with code {}", &oauth_req.code);
    let client_id = conf.get("github_client_id").unwrap();
    let client_secret = conf.get("github_client_secret").unwrap();
    let oauth_result = github_oauth(client_id.clone(), client_secret.clone(), oauth_req.code.clone());

    persistence::insert_user_oauth2(
        &endex.db_pool, 
        &endex.conf,
        persistence::UserOAuth {
            kid: oauth_req.account.clone(),
            org: oauth_req.org.to_string(),
            tee_profile: oauth_result.to_string(),
            tee_profile_size: 256
        }
    );
    HttpResponse::Ok().json(OAuthResp{
        profile: oauth_result
    })
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
