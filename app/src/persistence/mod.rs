use mysql::*;
use mysql::prelude::*;

use std::fs::File;
use std::fs;

use glob::glob;
use std::io::Write;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub kid: String,
    pub uname: String,
    pub email: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuth {
    pub kid: String,
    pub org: String,
    pub oprofile: String
}

pub fn insert_user(pool: &Pool, user: User) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("delete from user where kid = ?",
        (user.kid.clone(),)).unwrap();
    tx.exec_drop("insert into user (kid, uname, email) values (?, ?, ?)",
        (user.kid, user.uname, user.email)).unwrap();
    tx.commit().unwrap();
}

pub fn insert_oauth(pool: &Pool, oauth: OAuth) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("delete from oauth where kid = ? and org = ?",
        (oauth.kid.clone(), oauth.org.clone())).unwrap();
    tx.exec_drop("insert into oauth (kid, org, oprofile) values (?, ?, ?)",
        (oauth.kid, oauth.org, oauth.oprofile)).unwrap();
    tx.commit().unwrap();
}

pub fn delete_oauth(pool: &Pool, oauth: OAuth) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("delete from oauth where kid = ? and org = ?",
        (oauth.kid.clone(), oauth.org.clone())).unwrap();
    tx.commit().unwrap();
}

pub fn query_user(pool: &Pool, stmt: String) -> Vec<User>{
    let mut conn = pool.get_conn().unwrap();
    let mut result: Vec<User> = Vec::new();
    conn.query_iter(stmt).unwrap().for_each(|row| {
        let r:(std::string::String, 
            std::string::String, 
            std::string::String) = from_row(row.unwrap());
        result.push(User {
            kid: r.0,
            uname: r.1,
            email: r.2,
        });
    });
    result
}

pub fn query_oauth(pool: &Pool, stmt: String) -> Vec<OAuth>{
    let mut conn = pool.get_conn().unwrap();
    let mut result: Vec<OAuth> = Vec::new();
    conn.query_iter(stmt).unwrap().for_each(|row| {
        let r:(std::string::String, 
            std::string::String, 
            std::string::String) = from_row(row.unwrap());
        result.push(OAuth {
            kid: r.0,
            org: r.1,
            oprofile: r.2,
        });
    });
    result
}
