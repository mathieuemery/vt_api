use std::env;
use std::process::Command;
use serde_json::Value;
use regex::Regex;

use crate::resolve::domain_collector;
use crate::resolve::ip_collector;

pub fn request() -> String {
    // Get the command line arguments
    let args: Vec<String> = env::args().collect();
    // Get the API key from the environment variable
    let api_key = env::var("VT_API_KEY").expect("API key not set");

    if args.len() < 3 {
        eprintln!("Usage: {} <COMMAND> <data>", args[0]);
        std::process::exit(1);
    }

    // Parse arguments
    let data = &args[2];

    let result;
    let summary;

    // Checks the type of data that has been given by the user
    let data_type = get_type(&data);

    if data_type.eq("ip") {
        result = fetch_ip_info(&data, &api_key).expect("Couldn't execute the request command");
        summary = ip_collector::collector(&result.to_string(), &data, &data_type);
    } else if data_type.eq("domain") {
        result = fetch_domain_info(&data, &api_key).expect("Couldn't execute the request command");
        summary = domain_collector::collector(&result.to_string(), &data, &data_type);
    } else {
        eprintln!("Invalid data");
        std::process::exit(1);
    }

    let data = summary.unwrap();
    println!("{}", data);
    "".to_string()
    //serde_json::to_string_pretty(data).unwrap()
}

/// Fetch the report from the virus total API using CURL for a domain
/// Specify that we expect a json value
/// -s # --silent: don't show progress meter or errors
fn fetch_domain_info(domain: &str, api_key: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // Run the `curl` command
    let output = Command::new("curl")
        .arg("-s")
        .arg("-X")
        .arg("GET")
        .arg(format!("https://www.virustotal.com/api/v3/domains/{}", domain))
        .arg("-H")
        .arg(format!("x-apikey: {}", api_key))
        .arg("-H")
        .arg("Accept: application/json")
        .output()?;

    // Check if the command was successful
    if !output.status.success() {
        eprintln!("Command failed with error: {:?}", output.stderr);
        return Err("Failed to fetch data from VirusTotal".into());
    }

    // Parse the JSON output
    let json: Value = serde_json::from_slice(&output.stdout)?;

    Ok(json)
}

/// Fetch the report from the virus total API using CURL for an IP
/// Specify that we expect a json value
/// -s # --silent: don't show progress meter or errors
fn fetch_ip_info(ip: &str, api_key: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // Run the `curl` command
    let output = Command::new("curl")
        .arg("-s")
        .arg("-X")
        .arg("GET")
        .arg(format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip))
        .arg("-H")
        .arg(format!("x-apikey: {}", api_key))
        .arg("-H")
        .arg("Accept: application/json")
        .output()?;

    // Check if the command was successful
    if !output.status.success() {
        eprintln!("Command failed with error: {:?}", output.stderr);
        return Err("Failed to fetch data from VirusTotal".into());
    }

    // Parse the JSON output
    let json: Value = serde_json::from_slice(&output.stdout)?;

    Ok(json)
}

/// Checks the structure of a string using regular expressions.
/// If the string contains a valid IPv4 address, returns "ip".
/// Else if the user entry is a valid domain, returns "domain".
/// Else, return an empty string to indicate that the parameter is invalid.
///
/// # Examples
///
/// ```
/// let domain = "google.com";
/// let ip = "8.8.8.8";
/// let something_else = "";
///
/// assert_eq!("domain".to_string(), get_type(&domain));
/// assert_eq!("ip".to_string(), get_type(&ip));
/// assert_eq!("".to_string(), get_type(&something_else));
/// ```
fn get_type(value: &str) -> String{
    // Regular expression for IPv4 address
    let ipv4_regex = Regex::new(
        r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ).unwrap();

    // Regular expression for domains
    let domain_regex = Regex::new(
        r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$"
    ).unwrap();

    // Check if the user entry is an IP or a domain
    if ipv4_regex.is_match(value){
        "ip".to_string()
    }
    else if domain_regex.is_match(value){
        "domain".to_string()
    }
    else{
        "".to_string()
    }
}