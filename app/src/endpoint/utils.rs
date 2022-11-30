use std::collections::HashMap;
use serde_derive::{Deserialize, Serialize};
use std::time::SystemTime;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};


/// Get system time now in u64 format
pub fn system_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

/// Sendmail using account in config file
/// to account in args
pub fn sendmail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    if conf.get("env").unwrap() == "dev" {
        info!("send mail {} to {}", msg, account);
        return 0;
    }
    if conf.contains_key("proxy_mail") {
        return proxy_mail(account, msg, conf);
    }
    info!("send mail {} to {}", msg, account);
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
        Ok(_) => { info!("Email sent successfully!"); return 0 },
        Err(e) => { error!("Could not send email: {:?}", e); return 1 },
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

/// Sendmail through proxy server when mail-server got blocked.
pub fn proxy_mail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    info!("calling proxy mail {} {}", account, msg);
    let proxy_mail_server = conf.get("proxy_mail_server").unwrap();
    let client = reqwest::blocking::Client::new();
    let proxy_mail_req = ProxyMailReq {
        account: account.to_owned(),
        msg: msg.to_owned()
    };
    let res = client.post(proxy_mail_server)
        .json(&proxy_mail_req)
        .send().unwrap().json::<ProxyMailResp>().unwrap();
    if res.status == "success" {
        return 0;
    }
    return 1;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_time() {
        let current = system_time();
        let future = system_time();
        assert!(current <= future);
    }

}
