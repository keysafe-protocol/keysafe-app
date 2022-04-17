extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use std::io::Write;
use sgx_urts::SgxEnclave;
use std::ffi::CString;
use std::ffi::CStr;

extern {

    pub fn ec_gen_key(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t
    ) -> sgx_status_t;

    pub fn ec_ks_exchange(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        user_pub_key: *const c_char,
        strval: *mut c_void,
        strval2: *mut c_void
    ) -> sgx_status_t;

    pub fn ec_ks_seal(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        some_string: *const c_char,
        len1: u32,
        text: *const c_char,
        len2: u32,
        strval: *mut c_void,
        len3: u32
    ) -> sgx_status_t;

    pub fn ec_ks_unseal(
        eid: sgx_enclave_id_t, 
        retval: *mut u32,
        user_pub_key: *const c_char,
        sealed: *const c_char,
        len3: u32
    ) -> sgx_status_t;

    pub fn ec_prove_me(
        eid: sgx_enclave_id_t, 
        retval: *mut u32,
        code: *const c_char,
        code_len: u32,
        unsealed: *mut c_void
    ) -> sgx_status_t;

    pub fn ec_calc_sealed_size(
        eid: sgx_enclave_id_t, 
        retval: *mut u32,
        len1: u32
    ) -> sgx_status_t;

    pub fn ec_gen_gauth_secret(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        sealed_secret: *mut c_void,
        len1: u32,
        encrypted_secret: *mut c_void
    ) -> sgx_status_t;

    pub fn ec_check_code(
        eid: sgx_enclave_id_t, 
        retval: *mut u32,
        secret: *const c_char,
        secret_len: u32,
        tm: u64,
        code: *const c_char,
        code_len: u32,
        data: *const c_char,
        data_len: u32,
        unsealed: *mut c_void
    ) -> sgx_status_t;

}

