use clap::Parser;
use console::style;
use reqwest::{Client, Error, header::{CONTENT_TYPE, AUTHORIZATION, ACCEPT}, redirect};
use serde::{Serialize, Deserialize};
use tokio::{self, time::{Sleep, sleep}};
use std::{error::Error as stdError, time::Duration, io::BufReader, io, io::BufRead};
use regex::{Regex, Replacer};
use mac_address::get_mac_address;
use std::fs::File;
use std::path::Path;
use urlencoding::encode;

#[derive(Parser, Default, Debug)]
#[clap(author, version, about)]
///a cli tool for sniping minecraft usernames
struct Arguments {
    ///Your private key
    private_key: String,

    ///Your accounts.txt config
    accounts: String,

    #[clap(short, long)]
    ///The username to snipe
    snipe: Option<String>,

    #[clap(short, long)]
    ///Path to the username wordlist you want to check
    username_list: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticatePost {
    login: String,
    loginfmt: String,
    password: String,
    ppft: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct XboxPropertiesPost {
    AuthMethod: String,
    SiteName: String,
    RpsTicket: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct XboxPost {
    Properties: XboxPropertiesPost,
    RelyingParty: String,
    TokenType: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PropertiesPost {
    SandboxId: String,
    UserTokens: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct XSTSPost {
    Properties: PropertiesPost,
    RelyingParty: String,
    TokenType: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct XboxJson {
    IssueInstant: String,
    NotAfter: String,
    Token: String,
    DisplayClaims: DisplayStruct,
}

#[derive(Debug, Serialize, Deserialize)]
struct DisplayStruct {
    xui: xuiLMAO,
}

#[derive(Debug, Serialize, Deserialize)]
struct xuiLMAO {
    uhs: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BearerPost {
    identityToken: String,
    ensureLegacyEnabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyPost {
    key: String,
    unique: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn stdError>> {
    let args = Arguments::parse();
    logo();

    //verify key
    if !verify_key(args.private_key).await? {
        return Err(format!("Key validation failed!").into());
    }
    else {
        let validated_str = style("Key validation successful").cyan();
        println!("{}", validated_str);
    }

    if(args.snipe.is_some() && args.username_list.is_some()) {
        return Err(format!("Only use one flag at a time").into());
    }

    //get bearer tokens from file
    let bearer_tokens = get_bearer_tokens_from_config(args.accounts).await?;
    
    //check flags & then direct control flow
    
    if(args.snipe.is_some()) {
        println!("{}", style("Sniping username...").cyan());
        snipe_username(args.snipe.unwrap(), bearer_tokens).await?;
    }
    else if(args.username_list.is_some()) {

        println!("{}", style("Testing usernames from file...").cyan());
        let verified = wordlist_verify(args.username_list.unwrap(), bearer_tokens).await?;

        for string in verified.iter() {
            println!("{} Valid", string);
        }
    }

    Ok(())
}

fn logo() {
    
    let logo_str = style("
     _____       _            __  __  _____  
    / ____|     (_)          |  \\/  |/ ____| 
   | (___  _ __  _ _ __   ___| \\  / | |      
    \\___ \\| '_ \\| | '_ \\ / _ \\ |\\/| | |      
    ____) | | | | | |_) |  __/ |  | | |____  
   |_____/|_| |_|_| .__/ \\___|_|  |_|\\_____| 
                  | |                        
                  |_|                        
    ").color256(93);

    println!("{}", logo_str);

}

//verifies that the key & unique id are valid
async fn verify_key(key: String) -> Result<bool, Box<dyn stdError>> {
    let server = "http://localhost:3000/api/verify/";
    let unique_identifier = get_mac_address().unwrap().unwrap().to_string();

    let verify_post = VerifyPost {
        key: key,
        unique: unique_identifier,
    };

    let client = Client::new();
    let response = client.post(server).json(&verify_post).send().await?;
    let status = response.status().as_u16();

    match status {
        200 => return Ok(true),
        401 => return Err(format!("Key is not valid").into()),
        402 => return Err(format!("HWID Error, contact stackcollisions#2547 if this is a mistake").into()),
        _ => return Err(format!("Server error").into()),
    };
}

async fn get_bearer_tokens_from_config(file_path: String) -> Result<Vec<String>, Box<dyn stdError>>{
    let mut tokens = Vec::new();

    let path = Path::new(&file_path); 
    let file = File::open(&path);
    if(file.is_err()) {
        return Err(format!("Path supplied is not valid").into());
    }
    let file = file.unwrap();
    
    let reader = BufReader::new(file);

    for line in reader.lines() {
        if(line.is_err()) {
            return Err(format!("Error parsing file").into());
        }
        let line = line.unwrap();
        let mut parts = line.splitn(2,':');

        let user = parts.next().unwrap_or("");
        let pass = parts.next().unwrap_or("");

        if(!user.is_empty() && !pass.is_empty()) {
            let bearer = get_bearer(String::from(user), String::from(pass)).await?;
            sleep(Duration::from_millis(1000));
            tokens.push(bearer);
        }
        else {
            if(tokens.is_empty()) {
                return Err(format!("Error parsing (empty?)").into())
            }
            return Ok(tokens);
        }
    }

    return Ok(tokens);
}

async fn get_bearer(username: String, password: String) -> Result<String, Box<dyn stdError>> {
    //authenticate with mojang servers TODO: you need to get the bearer token every 24 hours using refresh token || just do this again
    let client = Client::builder().cookie_store(true).build().unwrap();
    let url = "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en";
    let response = client.get(url).send().await?;
    let body = response.text().await?;

    let value_regex = Regex::new(r#"value="(.+?)""#).unwrap();
    let value = value_regex
        .captures(body.as_str())
        .and_then(|cap| cap.get(1))
        .map_or("", |m| m.as_str())
        .to_string();


    let url_regex = Regex::new(r#"urlPost:'(.+?)'"#).unwrap();
    let mut url = url_regex
        .captures(body.as_str())
        .and_then(|cap| cap.get(1))
        .map_or("", |m| m.as_str())
        .to_string();

    //println!("Pass: {}", password);
    //let password = fix_quote(password);
    let encoded_email = encode(&username).to_string();
    let encoded_password = encode(&password).to_string();
    let auth_post = AuthenticatePost {
        login: encoded_email.clone(),
        loginfmt: encoded_email,
        password: encoded_password,
        ppft: value,
    };

    let urlAppend = format!("login={}&loginfmt={}&passwd={}&PPFT={}", auth_post.login, auth_post.login, auth_post.password, auth_post.ppft);
    //println!("url: {}", urlAppend);
    let response = client.post(url).header(CONTENT_TYPE, "application/x-www-form-urlencoded").body(urlAppend).send().await?;

    let response_url = response.url().as_str();    
    //println!("URL: {}", response_url);
    //println!("{}", &password);
    if(!response_url.contains("access_token")) {
        //let failed_str = style("Failed to authenticate with mojang (invalid credentials or 2FA enabled").red();
        //println!("{}", failed_str);
        return Err(format!("Failed to authenticate {} with mojang (invalid credentials or 2FA enabled)", username).into());
    }

    let access_token_regex = Regex::new(r"#access_token=([^&]+)").unwrap();
    let caps = access_token_regex.captures(response_url).unwrap();
    let access_token = caps[1].to_string(); 


    //xbox sign in
    let xbox_url = "https://user.auth.xboxlive.com/user/authenticate";
    let xbox_properties = XboxPropertiesPost {
        AuthMethod: String::from("RPS"),
        SiteName: String::from("user.auth.xboxlive.com"),
        RpsTicket: access_token.clone(),
    };

    let xbox_post = XboxPost {
        Properties: xbox_properties,
        RelyingParty: String::from("http://auth.xboxlive.com"),
        TokenType: String::from("JWT"),
    };

    let response = client.post(xbox_url).header(CONTENT_TYPE, "application/json").header(ACCEPT, "application/json").json(&xbox_post).send().await?;
    let body = json::parse(response.text().await?.as_str()).unwrap();
    //println!("xbox: {:?}", body);
    let mut xbox_token = String::new();
    let mut user_hash = String::new();
    for val in body.entries() {
        if val.0.contains("Token") {
            xbox_token = val.1.to_string();
        }
        else if val.0.contains("DisplayClaims") {
            for val2 in val.1.entries() {
                user_hash = val2.1.to_string();
            }
        }
    }
    let user_hash_regex = Regex::new(r#"\d+"#).unwrap();
    let numbers: Vec<String> = user_hash_regex
        .find_iter(user_hash.as_str())
        .map(|m| m.as_str().to_string())
        .collect();


    let user_hash = &numbers[0];
    
    let mut userTokens = Vec::new();
    userTokens.push(xbox_token);
    let prop = PropertiesPost {
        SandboxId: String::from("RETAIL"),
        UserTokens: userTokens,
    };

    let xsts = XSTSPost {
        Properties: prop,
        RelyingParty: String::from("rp://api.minecraftservices.com/"),
        TokenType: String::from("JWT"),
    };

    let xsts_url = "https://xsts.auth.xboxlive.com/xsts/authorize";
    let response = client.post(xsts_url).header(CONTENT_TYPE, "application/json").header(ACCEPT, "application/json").json(&xsts).send().await?;

    let body = json::parse(response.text().await?.as_str()).unwrap();
    //println!("BODY: {:?}", body);
    //println!("\nHASH: {}\n", user_hash);
    let mut xsts_token = String::new();
    for val in body.entries() {
        if val.0.contains("Token") {
            xsts_token = val.1.to_string();
            break;
        }
    }

    //GET THE BEARER TOKEN FINALLY
    let bearer_url = "https://api.minecraftservices.com/authentication/login_with_xbox";
    let bearer_post = BearerPost {
        identityToken: format!("XBL3.0 x={};{}", user_hash, xsts_token),
        ensureLegacyEnabled: true,
    };

    let response = client.post(bearer_url).header(CONTENT_TYPE, "application/json").json(&bearer_post).send().await?;
    //println!("FINAL: {:?}", response);

    let body = json::parse(response.text().await?.as_str()).unwrap();

    let mut access_token = String::new();
    for var in body.entries() {
        if var.0.contains("access_token") {
            let validated_str = style(format!("{} login success", username)).green();
            println!("{}", validated_str);
            return Ok(var.1.to_string());
            access_token = var.1.to_string();
        }
    }

    Err(format!("Error getting bearer token!").into())
}

async fn wordlist_verify(path: String, bearer_tokens: Vec<String>) -> Result<Vec<String>, Box<dyn stdError>>{
    let mut available_usernames = Vec::new();
    let mut all_names_in_list = Vec::new();

    let path = Path::new(&path); 
    let file = File::open(&path);
    if(file.is_err()) {
        return Err(format!("Path supplied for username list").into());
    }
    let file = file.unwrap();
    
    let reader = BufReader::new(file);


    for username in reader.lines() {
        if(username.is_err()) {
            return Err(format!("Error parsing file").into());
        }
        let username = username.unwrap();


        if(!username.is_empty()) {
            all_names_in_list.push(username);
        }
        else {
            break;
        }
    }

    let sleep_millis: u64 = 7000;
    let account_count: u64 = bearer_tokens.len().try_into().unwrap();
    let sleep_time = Duration::from_millis(sleep_millis/account_count);

    //println!("Sleep: {:?}", sleep_time);


    while !all_names_in_list.is_empty() {
        for bearer_token in bearer_tokens.iter() {
            let curr_username = all_names_in_list.pop().unwrap();
            let taken = is_username_taken(String::from(bearer_token), curr_username.clone()).await?;
            //println!("{}", curr_username);
            match taken {
                true => {
                    println!("{}", style(format!("{} Not Available", curr_username)).red());
                    sleep(sleep_time).await;
                    continue;
                }
                false => {
                    println!("{}", style(format!("{}",curr_username)).green());
                    sleep(sleep_time).await;
                    available_usernames.push(curr_username);
                }
            }
        }
    }

    return Ok(available_usernames);
}

async fn is_username_taken(bearer_token: String, username: String) -> Result<bool, Box<dyn stdError>> {
    let url = format!("https://api.minecraftservices.com/minecraft/profile/name/{}/available", username);
    let client = Client::new();
    let response = client.get(url).header(AUTHORIZATION, format!("Bearer {}", bearer_token)).send().await;
    if response.is_err() {
        return Err(format!("Failed to check if username is taken").into());
    }

    let response_body = response.unwrap().text().await?;

    if response_body.contains("AVAILABLE") {
        return Ok(false);
    }
    else if response_body.contains("DUPLICATE") {
        return Ok(true);
    }
    else if response_body.contains("NOT_ALLOWED") {
        return Ok(true);
    }
    else if response_body.contains("CONSTRAINT_VIOLATION") {
        return Ok(true);
    }
    else {
    }

    return Err(format!("Invalid response from server (code: 400)").into());
}

async fn snipe_username(username: String, bearer_tokens: Vec<String>) -> Result<bool, Box<dyn stdError>> {

    let sleep_millis: u64 = 7000;
    let account_count: u64 = bearer_tokens.len().try_into().unwrap();
    let sleep_time = Duration::from_millis(sleep_millis/account_count);

    let mut name_gotten = false;
    let client = Client::builder().cookie_store(true).build().unwrap();
    let name_available_url = format!("https://api.minecraftservices.com/minecraft/profile/name/{}/available", username);
    while !name_gotten {
        
        for bearer_token in bearer_tokens.iter() {
            let response = client.get(&name_available_url).header("Authorization", format!("Bearer {}", bearer_token)).send().await?.text().await?;

            if(response.contains("AVAILABLE")) {
                //snag user
                let response = client.put(format!("https://api.minecraftservices.com/minecraft/profile/name/{}", username)).header(AUTHORIZATION, format!("Bearer {}", bearer_token)).send().await?;
                match (response.status().as_u16()) {
                    200 => {
                        let success_str = style(format!("Sucessfully got {}", username)).magenta();
                        println!("{}", success_str);
                        return Ok(true);
                    }
                    400 => {
                        return Err(format!("Username invalid").into());
                    }
                    403 => {
                        return Err(format!("Failed to fetch username, you missed it").into());
                    }
                    _ => {
                        return Err(format!("Failed to get username Error: 150").into());
                    }
                }
            }
            else if response.contains("NOT_ALLOWED") {
                //handle username not allowed
                return Err(format!("The username you selected is not allowed by mojang").into());
            }
            else if response.contains("DUPLICATE") {
                //continue looping
                sleep(sleep_time).await;
                continue;
            }

        }

    }


    return Ok(true);
}
