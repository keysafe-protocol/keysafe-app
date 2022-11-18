use std::{convert::TryFrom, str::FromStr};
use std::{thread, time};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde_derive::{Deserialize, Serialize};
use actix_web::{
    get, post, web, Error, HttpRequest, HttpResponse, 
    Responder, FromRequest, http::header::HeaderValue, 
    http::header::TryIntoHeaderValue, http::header::InvalidHeaderValue};
use crate::endpoint::utils;


/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // acount name
    pub exp: usize, // when to expire
}


pub fn verify_token(token_option: Option<&HeaderValue>, secret: &str) -> bool {
    if let Some(v) = token_option {
        println!("analyze header {} with {}", v.to_str().unwrap(), secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
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


pub fn extract_token(token_option: Option<&HeaderValue>, 
    secret: &str) -> Option<Claims> {
    if let Some(v) = token_option {
        println!("analyze header {} with {}", v.to_str().unwrap(), secret);
        let mut validation = Validation::new(Algorithm::HS256);
        let token = v.to_str().unwrap();
        let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &validation);
        match token_data {
            Ok(t) => Some(t.claims),
            _ => {
                println!("token verify failed");
                None
            }
        }
    } else {
        println!("extract token from header failed");
        None
    }        
}


pub fn gen_token(account: &str, secret: &str) -> String {
    gen_token_n(account, secret, 7 * 24 * 3600)
}


fn gen_token_n(account: &str, secret: &str, n: u64) -> String {
    println!("{}", utils::system_time());
    encode(
        &Header::default(), 
        &Claims{
            sub: account.to_string(),
            exp: (utils::system_time() + n).try_into().unwrap()
        },
        &EncodingKey::from_secret(secret.to_string().as_bytes()),
    ).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_token() {
        let token1 = gen_token("abc", "rust123");
        println!("{}", token1);
        let header = HeaderValue::from_str(&token1).unwrap();
        let secret = "rust123";
        // data is "account": "admin@keysafe.network"
        let verify_result = verify_token(Some(&header), &secret);
        assert!(verify_result);
    }

    #[test]
    fn test_verify_invalid_token() {
        let token1 = "invalid token string";
        println!("{}", token1);
        let header = HeaderValue::from_str(&token1).unwrap();
        let secret = "rust123";
        // data is "account": "admin@keysafe.network"
        let verify_result = verify_token(Some(&header), &secret);
        assert_eq!(verify_result, false);
    }

    #[test]
    fn test_extract_token() {
        let token1 = gen_token("abc", "rust123");
        println!("{}", token1);
        let header = HeaderValue::from_str(&token1).unwrap();
        let secret = "rust123";
        // data is "account": "admin@keysafe.network"
        match extract_token(Some(&header), &secret) {
            Some(c) => {
                assert_eq!(c.sub, "abc")
            }, None => {
                panic!("tests failed")
            }
        }
    }

    #[test]
    fn test_extract_invalid_token() {
        let token1 = "some invalid token";
        println!("{}", token1);
        let header = HeaderValue::from_str(&token1).unwrap();
        let secret = "rust123";
        // data is "account": "admin@keysafe.network"
        match extract_token(Some(&header), &secret) {
            Some(c) => {
                panic!("test failed")
            },
            None => {
                assert!(true)
            }
        }
    }


    #[test]
    fn test_expired_token() {
        let token1 = gen_token_n("abc", "rust123", 1);
        let header = HeaderValue::from_str(&token1).unwrap();
        let secret = "rust123";
        // data is "account": "admin@keysafe.network"
        let one_sec = time::Duration::new(100, 0);
        thread::sleep(one_sec);
        assert_eq!(verify_token(Some(&header), &secret), false)
    }

}
