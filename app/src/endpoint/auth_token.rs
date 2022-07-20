use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde_derive::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};
use actix_web::{
    get, post, web, Error, HttpRequest, HttpResponse, 
    Responder, FromRequest, http::header::HeaderValue, 
    http::header::TryIntoHeaderValue, http::header::InvalidHeaderValue};
    
/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // acount name
    pub exp: usize, // when to expire
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

pub fn extract_token(token_option: Option<&HeaderValue>, 
    secret: &str) -> Option<Claims> {
    if let Some(v) = token_option {
        println!("analysing header {}", v.to_str().unwrap());
        println!("decode with secret {}", secret);
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

