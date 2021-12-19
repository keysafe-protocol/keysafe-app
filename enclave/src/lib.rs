// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate serde_json;
extern crate sgx_crypto_helper;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use sgx_crypto_helper::rsa2048::{Rsa2048KeyPair, Rsa2048PubKey};


#[no_mangle]
pub extern "C" fn register_key(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);
    let key_str = String::from_utf8(str_slice.to_vec()).unwrap();
    let rsa_pubkey: Rsa2048PubKey = serde_json::from_str(&key_str).unwrap();

    let mut ciphertext = Vec::new();
    let text = String::from("Hello, World.");
    let text_slice = &text.into_bytes();

    match rsa_pubkey.encrypt_buffer(text_slice, &mut ciphertext) {
        Ok(n) => println!("Generated secret with user pub key."),
        Err(x) => println!("Error occurred during encryption {}", x)
    }

    sgx_status_t::SGX_SUCCESS
}

