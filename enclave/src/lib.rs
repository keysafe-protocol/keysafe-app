#![crate_name = "enclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_trts;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate serde;
extern crate serde_json;
extern crate http_req;

#[cfg(target_env = "sgx")]
extern crate sgx_types;

use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use serde_json::Map;
use serde_json::Value;
use sgx_tcrypto::*;
use sgx_types::*;
use std::mem::MaybeUninit;
use std::ptr;
use std::slice;
use std::sync::{Once, SgxMutex};
use std::vec::Vec;
use std::ffi::CStr;
use std::net::TcpStream;
use http_req::{request::{RequestBuilder, Method}, tls, uri::Uri};
use std::string::String;
use std::string::ToString;
use std::backtrace::{self, PrintFormat};
use std::collections::HashMap;
// use std::prelude::v1::*;
// use sgx_tseal::{SgxSealedData};


struct EnclaveState {
    pub_k: sgx_ec256_public_t,
    prv_k: sgx_ec256_private_t,
    user_state: HashMap<String, String>
}


// Rust doesn't support mutable statics, as it could lead to bugs in a multithreading setting
// and it cannot prevent this. So we need to use a mutex even if we have one thread
struct SingletonReader {
    inner: SgxMutex<EnclaveState>,
}

fn singleton() -> &'static SingletonReader {
    // Create an uninitialized static
    static mut SINGLETON: MaybeUninit<SingletonReader> = MaybeUninit::uninit();
    static ONCE: Once = Once::new();
    unsafe {
        ONCE.call_once(|| {
            // initial public and private key, save both in static state
            let ecc_handle = SgxEccHandle::new();
            let _result = ecc_handle.open();
            let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();
        
            let singleton = SingletonReader {
                inner: SgxMutex::new(EnclaveState {
                    pub_k: pub_k,
                    prv_k: prv_k,
                    user_state: HashMap::new()
                }),
            };
            // Store it to the static var, i.e. initialize it
            SINGLETON.write(singleton);
        });
        // Now we give out a shared reference to the data, which is safe to use
        // concurrently.
        SINGLETON.assume_init_ref()
    }
}


#[no_mangle]
pub extern "C" fn ec_gen_key() -> sgx_status_t {
    println!("enclave is up and running.");
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn ec_ks_exchange(user_pub_key: *const c_char,
                                 tee_pub_key: &mut [u8;64]) -> sgx_status_t {
    if user_pub_key.is_null() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let upk = unsafe { CStr::from_ptr(user_pub_key).to_str() };
    let user_pub_key_tee = upk.expect("Failed to recover user pub key");
    println!("user_pub_key is {}", user_pub_key_tee);

    let enclave_state = singleton().inner.lock().unwrap();
    let k = [enclave_state.pub_k.gx, enclave_state.pub_k.gy].concat();
    println!("{:?}", k);
    *tee_pub_key = k.try_into().unwrap();

    sgx_status_t::SGX_SUCCESS
}

/*
#[no_mangle]
pub extern "C" fn ec_register_github_oauth(code: *const c_char,
                                           client_id: *const c_char,
                                           client_secret: *const c_char) -> sgx_status_t {
    println!("calling ec_register_github_oauth");
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);
    let tcode = unsafe { CStr::from_ptr(code).to_str() };
    let tclient_id = unsafe { CStr::from_ptr(client_id).to_str() };
    let tclient_secret = unsafe { CStr::from_ptr(client_secret).to_str() };
    github_oauth(tcode.unwrap(), tclient_id.unwrap(), tclient_secret.unwrap());
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_aes_gcm_128_encrypt(
    plaintext: *const u8,
    text_len: usize,
    ciphertext: *mut u8,
    mac: &mut [u8; 16],
) -> sgx_status_t {
    println!("aes_gcm_128_encrypt invoked!");

    let enclave_state = singleton().inner.lock().unwrap();
    let key = &enclave_state.key;
    let iv = &enclave_state.iv;

    // First, we need slices for input
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, text_len) };

    // Here we need to initiate the ciphertext buffer, though nothing in it.
    // Thus show the length of ciphertext buffer is equal to plaintext buffer.
    // If not, the length of ciphertext_vec will be 0, which leads to argument
    // illegal.
    let mut ciphertext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    // Here we cannot use slice::from_raw_parts because it provides &[u8]
    // instead of &[u8,16].
    let aad_array: [u8; 0] = [0; 0];
    let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];

    // Always check the length after slice::from_raw_parts
    if plaintext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let ciphertext_slice = &mut ciphertext_vec[..];
    //println!(
    //    "aes_gcm_128_encrypt parameter prepared! {}, {}",
    //    plaintext_slice.len(),
    //    ciphertext_slice.len()
    //);

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_encrypt(
        key,
        &plaintext_slice,
        iv,
        &aad_array,
        ciphertext_slice,
        &mut mac_array,
    );
    //println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(ciphertext_slice.as_ptr(), ciphertext, text_len);
            }
            *mac = mac_array;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// An AES-GCM-128 decrypt function sample.
///
/// # Parameters
///
/// **ciphertext**
///
/// Cipher text to be decrypted.
///
/// **text_len**
///
/// Length of cipher text.
///
/// **mac**
///
/// A pointer to source mac buffer, typed as &[u8;16].
///
/// **plaintext**
///
/// A pointer to destination plaintext buffer.
///
/// # Return value
///
/// **SGX_SUCCESS** on success
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** Indicates the parameter is invalid.
///
/// **SGX_ERROR_UNEXPECTED** means that decryption failed.
///
/// # Requirements
//
/// The caller should allocate the plaintext buffer. This buffer should be
/// at least same length as ciphertext buffer.
// comes from samplecode/crypto
#[no_mangle]
pub extern "C" fn ecall_aes_gcm_128_decrypt(
    ciphertext: *const u8,
    text_len: usize,
    mac: &[u8; 16],
    plaintext: *mut u8,
) -> sgx_status_t {
    println!("aes_gcm_128_decrypt invoked!");

    let enclave_state = singleton().inner.lock().unwrap();
    let key = &enclave_state.key;
    let iv = &enclave_state.iv;

    // First, for data with unknown length, we use vector as builder.
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    let aad_array: [u8; 0] = [0; 0];

    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let plaintext_slice = &mut plaintext_vec[..];
    //println!(
    //    "aes_gcm_128_decrypt parameter prepared! {}, {}",
    //    ciphertext_slice.len(),
    //    plaintext_slice.len()
    //);

    // After everything has been set, call API
    let result =
        rsgx_rijndael128GCM_decrypt(key, &ciphertext_slice, iv, &aad_array, mac, plaintext_slice);

    //println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => unsafe {
            ptr::copy_nonoverlapping(plaintext_slice.as_ptr(), plaintext, text_len);
        },
    }
    sgx_status_t::SGX_SUCCESS
}

/*
#[no_mangle]
pub extern "C" fn create_sealeddata_for_fixed(
    content: *const u8,
    content_size: u32,
    sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    let opt = from_sealed_log_for_fixed::<RandDataFixed>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let data = unsealed_data.get_decrypt_txt();

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS;

    let mut data = RandDataFixed::default();
    data.key = 0x1234;

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut data.rand);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<RandDataFixed>::seal_data(&aad, &data);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };

    let opt = to_sealed_log_for_fixed(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

fn from_sealed_log_for_fixed<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
*/

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

fn github_oauth(
    client_id: &str,
    client_secret: &str,
    code: &str
) -> String {
    let addr: Uri = "https://github.com/login/oauth/access_token".parse().unwrap();
    println!("{}", addr.host().unwrap());
    println!("{}", addr.corr_port());
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.corr_port());
    println!("conn_addr is {}", conn_addr);
    let stream = TcpStream::connect(conn_addr);
    match stream {
        Ok(r) => {
            let mut stream = tls::Config::default()
            .connect(addr.host().unwrap_or(""), r)
            .unwrap();
        
        let mut writer = Vec::new();
        let body = format!("{{\"client_id\":\"{}\", \"client_secret\":\"{}\", \"code\":\"{}\"}}",
            client_id, client_secret, code);
    
        let response = RequestBuilder::new(&addr)
            .method(Method::POST)
            .header("Accept", "application/json")
            .header("User-Agent", "keysafe-protocol")
            .header("Connection", "Close")
            .body(body.as_bytes())
            .send(&mut stream, &mut writer)
            .unwrap();
        
        let body = String::from_utf8_lossy(&writer);
        println!("access token response is {:?}", body);
        return body.to_string()    ;
        },
        Err(err) => {
            println!("{:?}", err);
            panic!("building TcpConnection failed");
        }
    };
}

*/

#[no_mangle]
pub extern "C" fn ec_gen_register_mail_code(
    account: *const c_char,
    cipher_code: *const c_char,
    cipher_size: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_register_mail(
    account: *const c_char,
    cipher_code: *const c_char,
    cipher_size: u32,
    sealed_mail: *mut c_void,
    sealed_size: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_register_password(
    account: *const c_char,
    cipher_code: *const c_char,
    cipher_size: u32,
    sealed_password: *mut c_void,
    sealed_size: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}
#[no_mangle]
pub extern "C" fn ec_register_gauth(
    account: *const c_char,
    cipher_gauth: *mut c_void,
    cipher_size: u32,
    sealed_gauth: *mut c_void,
    sealed_size: u32,
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_gen_gauth_secret(
    sealed_gauth: *mut c_char,
    sealed_size: u32,
    cipher_gauth: *mut c_char
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_verify_gauth_code(
    code: i32,
    gauth_secret: *const c_char,
    time: u64
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_ks_seal(
    account: *const c_char,
    cipher_secret: *const c_char,
    cipher_size: u32,
    sealed_secret: *mut c_void,
    sealed_size: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_ks_unseal2(
    account: *const c_char,
    cipher_cond: *const c_char, // user encrypted password or confirm code or etc
    cipher_cond_size: u32,
    cond_type: *const c_char,
    sealed_cond: *const c_char,
    sealed_cond_size: u32,
    sealed_secret: *const c_char,
    sealed_secret_size: u32,
    unsealed_secret: *mut c_void,
    unsealed_secret_size: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_ks_unseal(
    user_pub_key: *const c_char,
    sealed: *const c_char,
    len3: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_prove_me(
    code: *const c_char,
    code_len: u32,
    unsealed: *mut c_void
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_calc_sealed_size(
    len1: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_check_code(
    secret: *const c_char,
    secret_len: u32,
    tm: u64,
    code: *const c_char,
    code_len: u32,
    data: *const c_char,
    data_len: u32,
    unsealed: *mut c_void
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C"  fn ec_auth_confirm(
    account: *const c_char,
    cipher_code: *const c_char,
    cipher_size: u32
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_auth(
    account: *const c_char,
    user_pub_key: *const c_char
) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}