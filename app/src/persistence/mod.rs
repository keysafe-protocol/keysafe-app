use mysql::*;
use mysql::prelude::*;

use std::fs::File;
use std::fs;

use glob::glob;
use std::io::Write;

pub struct UserCond {
    pub kid: String,
    pub cond_type: String,
    pub tee_cond_value: String,
    pub tee_cond_size: i32
}

pub struct UserSecret {
    pub kid: String,
    pub cond_type: String,
    pub delegate_id: String,
    pub chain: String,
    pub chain_addr: String,
    pub tee_secret: String,
    pub tee_secret_size: i32
}

pub fn insert_user_cond(pool: &Pool, ucond: UserCond) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("delete from user_cond where kid = ? and cond_type = ?",
        (ucond.kid.clone(), ucond.cond_type.clone())).unwrap();
    tx.exec_drop("insert into user_cond (kid, cond_type, tee_cond_value, tee_cond_size) values (?, ?, ?, ?)",
        (ucond.kid, ucond.cond_type, ucond.tee_cond_value, ucond.tee_cond_size)).unwrap();
    tx.commit().unwrap();
}

pub fn insert_user_secret(pool: &Pool, usecret: UserSecret) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("delete from user_secret where kid = ? and cond_type = ?",
        (usecret.kid.clone(), usecret.cond_type.clone())).unwrap();
    tx.exec_drop(
        "insert into user_secret (kid, cond_type, chain, chain_addr, tee_secret, tee_secret_size) values (?, ?, ?, ?, ?, ?)",
        (usecret.kid, usecret.cond_type, usecret.chain, usecret.chain_addr, usecret.tee_secret, usecret.tee_secret_size)).unwrap();
    tx.commit().unwrap();
}

pub fn update_delegate(pool: &Pool, delegate_id: &String, kid: &String, chain: &String, chain_addr: &String) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("update user_secret set delegate_id = ? where kid = ? and chain = ? and chain_addr = ?",
        (delegate_id, kid, chain, chain_addr)).unwrap();
    tx.commit().unwrap();
}

pub fn query_user_cond(pool: &Pool, stmt: String) -> Vec<UserCond>{
    let mut conn = pool.get_conn().unwrap();
    let mut result: Vec<UserCond> = Vec::new();
    conn.query_iter(stmt).unwrap().for_each(|row| {
        let r:(std::string::String, std::string::String, 
            std::string::String, i32) = from_row(row.unwrap());
        result.push(UserCond {
            kid: r.0,
            cond_type: r.1,
            tee_cond_value: r.2,
            tee_cond_size: r.3
        });
    });
    result
}

pub fn query_user_secret(pool: &Pool, stmt: String) -> Vec<UserSecret> {
    let mut conn = pool.get_conn().unwrap();
    let mut result: Vec<UserSecret> = Vec::new();
    conn.query_iter(stmt).unwrap().for_each(|row| {
        let r:(std::string::String, std::string::String, 
            std::string::String, std::string::String, 
            std::string::String, std::string::String,
            i32
        ) = from_row(row.unwrap());
        result.push(
            UserSecret {
                kid: r.0,
                cond_type: r.1,
                delegate_id: r.2,
                chain: r.3,
                chain_addr: r.4,
                tee_secret: r.5,
                tee_secret_size: r.6
            }
        );
    });
    result
}

pub fn remove_previous_file(fname: &str) {
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

pub fn write_file(fname: &str, val: Vec<u8>, n: usize) {
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

pub fn read_file(filename: &String) -> Vec<u8> {
    let content = fs::read(filename);
    match content {
        Ok(x) => x,
        _ => panic!("read file failed.")
    }
}

pub fn check_sealed(filename: &String) -> u32 {
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
