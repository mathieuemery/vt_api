use serde::{Deserialize, Serialize};
use serde_json::Value;

// Store the full ip report summary
#[derive(Debug, Serialize, Deserialize)]
struct IPAnalysis {
    choice: String,
    ip_details: IPDetails,
    threat_analysis: ThreatAnalysis,
    network_info: NetworkInfo,
    certificate_info: CertificateInfo,
}

// Stores the basic data from an IP
#[derive(Debug, Serialize, Deserialize)]
struct IPDetails {
    ip_address: String,
    owner: String,
    country: String,
    continent: String,
}

// Threat analysis for the IP
#[derive(Debug, Serialize, Deserialize)]
struct ThreatAnalysis {
    total_votes: Votes,
    crowdsourced_threats: Vec<ThreatContext>,
    reputation_score: i32,
}

// Stores the count for each analysis result
#[derive(Debug, Serialize, Deserialize)]
struct Votes {
    harmless: u32,
    malicious: u32,
    suspicious: u32,
    timeout: u32,
    undetected: u32
}

// Store the context for the threat
#[derive(Debug, Serialize, Deserialize)]
struct ThreatContext {
    details: String,
    severity: String,
    source: String,
}

// Stores the network infos
#[derive(Debug, Serialize, Deserialize)]
struct NetworkInfo {
    network_range: String,
    registry: String,
    abuse_contact: String,
}

// Stores certificate infos
#[derive(Debug, Serialize, Deserialize)]
struct CertificateInfo {
    validity_period: String,
    issuer: String,
    alternative_names: Vec<String>,
}

/// Creates the summary from the raw report
pub fn collector(json_data: &str, arg: &str, choice: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Extract the data from the json report
    let json_value: Value = match serde_json::from_str(json_data) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Error while parsing JSON : {}", e);
            return Ok("".to_string())
        }
    };

    let analysis = analyze_ip_data(&json_value["data"]["attributes"], arg, choice);

    Ok(serde_json::to_string(&analysis)?)
}

/// Generates the IPAnalysis summary
fn analyze_ip_data(json_data: &Value, arg : &str, choice : &str) -> IPAnalysis {
    IPAnalysis {
        choice: choice.to_string(),
        ip_details: IPDetails {
            ip_address: arg.to_string(),
            owner: json_data["as_owner"].as_str().unwrap_or("Unknown").to_string(),
            country: json_data["country"].as_str().unwrap_or("Unknown").to_string(),
            continent: json_data["continent"].as_str().unwrap_or("Unknown").to_string(),
        },
        threat_analysis: ThreatAnalysis {
            total_votes: Votes {
                harmless: json_data["last_analysis_stats"]["harmless"].as_u64().unwrap_or(0) as u32,
                malicious: json_data["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0) as u32,
                suspicious: json_data["last_analysis_stats"]["suspicious"].as_u64().unwrap_or(0) as u32,
                undetected: json_data["last_analysis_stats"]["undetected"].as_u64().unwrap_or(0) as u32,
                timeout: json_data["last_analysis_stats"]["timeout"].as_u64().unwrap_or(0) as u32,
            },
            crowdsourced_threats: json_data["crowdsourced_context"]
                .as_array()
                .map_or(vec![], |threats| {
                    threats
                        .iter()
                        .map(|threat| ThreatContext {
                            details: threat["details"].as_str().unwrap_or("Unknown").to_string(),
                            severity: threat["severity"].as_str().unwrap_or("Unknown").to_string(),
                            source: threat["source"].as_str().unwrap_or("Unknown").to_string(),
                        })
                        .collect()
                }),
            reputation_score: json_data["reputation"].as_i64().unwrap_or(0) as i32,
        },
        network_info: NetworkInfo {
            network_range: json_data["network"].as_str().unwrap_or("Unknown").to_string(),
            registry: json_data["regional_internet_registry"].as_str().unwrap_or("Unknown").to_string(),
            abuse_contact: json_data["whois"]
                .as_str()
                .and_then(|whois| {
                    whois.lines()
                        .find(|line| line.contains("network-abuse@"))
                        .map(|line| line.trim().to_string())
                })
                .unwrap_or("Unknown".to_string()),
        },
        certificate_info: CertificateInfo {
            validity_period: format!(
                "{} to {}",
                json_data["last_https_certificate"]["validity"]["not_before"]
                    .as_str()
                    .unwrap_or("Unknown"),
                json_data["last_https_certificate"]["validity"]["not_after"]
                    .as_str()
                    .unwrap_or("Unknown")
            ),
            issuer: json_data["last_https_certificate"]["issuer"]["O"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            alternative_names: json_data["last_https_certificate"]["extensions"]["subject_alternative_name"]
                .as_array()
                .map_or(vec![], |names| {
                    names
                        .iter()
                        .filter_map(|name| name.as_str().map(|s| s.to_string()))
                        .collect()
                }),
        },
    }
}