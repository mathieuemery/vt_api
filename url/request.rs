use std::env;
use std::process::Command;
use serde_json::Value;
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;

use crate::url::collector;

/// Fetch data from the Virus Total API and generates a summary
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
    let url = &args[2];

    // Check the structure of the user's entry
    if get_type(&url).to_string() == "" {
        eprintln!("Error: not a valid URL");
        std::process::exit(1);
    }
    else{
        // Encode the URL to send it to the API
        let encoded : String = encode_url_in_base64(&get_type(&url).to_string());
        // Fetch the data from the API
        let result = fetch_virustotal_data(&encoded, &api_key).expect("Couldn't execute the request command");

        let data = &result["data"]["attributes"];

        // Creates a summary for the full report
        let summary = collector::collector(&serde_json::to_string_pretty(data).unwrap());

        summary.unwrap()
    }

}

/// Checks the structure of a string using regular expressions.
/// If the string contains a valid URL, returns it.
/// Else if the user entry is a domain, adds a 'https' in front.
/// Else, return an empty string to indicate that the parameter is invalid.
///
/// # Examples
///
/// ```
/// let domain = "google.com";
/// let something_else = "Hello World !";
///
/// assert_eq!("https://www.google.com".to_string(), get_type(&domain));
/// assert_eq!("".to_string(), get_type(&something_else));
/// ```
fn get_type(value: &str) -> String{
    // Regular expression for URLs
    let url_regex_http = Regex::new(
        r"^https?://(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&/=]*)$"
    ).unwrap();

    // Regular expression for domains without the http/https
    let url_regex = Regex::new(
        r"^[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&/=]*)$"
    ).unwrap();

    // Check if the user entry is a URL or a domain
    if url_regex_http.is_match(value){
        value.to_string()
    }
    else if url_regex.is_match(value){
        // Adds the https in front of the domain
        let mut result = "https://".to_string();
        result += value;
        result
    }
    else{
        "".to_string()
    }
}

/// Fetch the report from the virus total API using CURL.
/// Specify that we expect a json value
/// -s # --silent: don't show progress meter or errors
fn fetch_virustotal_data(url_id: &str, api_key: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // Run the `curl` command
    let output = Command::new("curl")
        .arg("-s")
        .arg("-X")
        .arg("GET")
        .arg(format!("https://www.virustotal.com/api/v3/urls/{}", url_id))
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

/// Encode a URL in base64
///
/// # Example
///
/// ```
/// let var = "https://www.google.com"
/// assert_eq!("aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ".to_string(), var);
/// ```
fn encode_url_in_base64(url: &str) -> String {
    // Encode the URL in Base64 URL-safe format and remove padding (=)
    general_purpose::URL_SAFE.encode(url).trim_end_matches('=').to_string()
}