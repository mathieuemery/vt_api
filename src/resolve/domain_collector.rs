use serde::{Deserialize, Serialize};
use serde_json::{Value};
use std::collections::HashMap;

// Stores the count for each analysis result
#[derive(Debug, Serialize, Deserialize)]
struct LastAnalysisStats {
    harmless: u32,
    malicious: u32,
    suspicious: u32,
    timeout: u32,
    undetected: u32,
}

// Stores the data from a DNS record
#[derive(Debug, Serialize, Deserialize)]
struct DnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u32>,
}

// Stores the public key data
#[derive(Debug, Serialize, Deserialize)]
struct PublicKey {
    algorithm: String,
    rsa: RsaDetails,
}

// Stores the RSA parameters
#[derive(Debug, Serialize, Deserialize)]
struct RsaDetails {
    key_size: u32,
    exponent: String,
}

// Stores data about the certificate
#[derive(Debug, Serialize, Deserialize)]
struct CertificateDetails {
    issuer: HashMap<String, String>,
    subject: HashMap<String, String>,
    validity: HashMap<String, String>,
    public_key: PublicKey,
    subject_alternative_name: Option<Vec<String>>,
}

// Stores all the different results
#[derive(Debug, Serialize, Deserialize)]
struct DetailedDomainReport {
    choice : String,
    domain: Option<BaseData>,
    analysis_stats: LastAnalysisStats,
    dns_records: DnsRecordSummary,
    ssl_certificate: Option<SslCertificateSummary>,
}

// Stores all the data from the DNS
#[derive(Debug, Serialize, Deserialize)]
struct DnsRecordSummary {
    a_records: Vec<String>,
    mx_records: Vec<String>,
    ns_records: Vec<String>,
    txt_records: Vec<String>,
    soa_records: Vec<String>,
}

// Stores data about the SSL certificate
#[derive(Debug, Serialize, Deserialize)]
struct SslCertificateSummary {
    issuer: String,
    validity_start: String,
    validity_end: String,
    key_type: String,
    key_size: u32,
    alternative_names: Vec<String>,
}

// Stores the other data from the report
#[derive(Debug, Serialize, Deserialize)]
struct BaseData{
    domain: String,
    categories: Option<HashMap<String, String>>,
    //admin_country: String,
    //organization: String,
    last_analysis_date: Option<u64>,
}

/// Creates the summary from the raw report
pub fn collector(content : &String, arg: &str, choice : &str) -> Result<String, Box<dyn std::error::Error>> {
    // Read the Virus Total report
    let raw_report: Value = serde_json::from_str(&content)?;
    let data = &raw_report["data"]["attributes"];

    // Creates a structured report
    let report = DetailedDomainReport {
        choice: choice.to_string(),
        domain: extract_base_data(&data, arg),
        analysis_stats: extract_analysis_stats(&data),
        dns_records: extract_dns_records(&data),
        ssl_certificate: extract_ssl_certificate(&data),
    };

    // Returns the result as a JSON
    Ok(serde_json::to_string_pretty(&report).unwrap())
}

/// Extract the basic data from the report
fn extract_base_data(raw_report: &Value, arg : &str) -> Option<BaseData> {
    Some(BaseData {
        domain: arg.to_string(),
        categories: serde_json::from_value(raw_report["categories"].clone()).unwrap(),
        last_analysis_date: raw_report["last_analysis_date"].as_u64()
    })
}

/// Get the analysis stats in the LastAnalysisStats structure
fn extract_analysis_stats(raw_report: &Value) -> LastAnalysisStats {
    serde_json::from_value(raw_report["last_analysis_stats"].clone()).unwrap_or_else(|_| LastAnalysisStats {
        harmless: 0,
        malicious: 0,
        suspicious: 0,
        timeout: 0,
        undetected: 0,
    })
}

/// Extract and store the dns records data in the DnsRecordSummary structure
fn extract_dns_records(raw_report: &Value) -> DnsRecordSummary {
    let dns_records = raw_report["last_dns_records"].as_array()
        .cloned()
        .unwrap_or_default();

    DnsRecordSummary {
        a_records: dns_records
            .iter()
            .filter(|r| r["type"] == "A")
            .map(|r| r["value"].as_str().unwrap_or_default().to_string())
            .collect(),
        mx_records: dns_records
            .iter()
            .filter(|r| r["type"] == "MX")
            .map(|r| r["value"].as_str().unwrap_or_default().to_string())
            .collect(),
        ns_records: dns_records
            .iter()
            .filter(|r| r["type"] == "NS")
            .map(|r| r["value"].as_str().unwrap_or_default().to_string())
            .collect(),
        txt_records: dns_records
            .iter()
            .filter(|r| r["type"] == "TXT")
            .map(|r| r["value"].as_str().unwrap_or_default().to_string())
            .collect(),
        soa_records: dns_records
            .iter()
            .filter(|r| r["type"] == "SOA")
            .map(|r| r["value"].as_str().unwrap_or_default().to_string())
            .collect(),
    }
}

/// Extract and store the SSL certificate data into the SslCertificateSummary structure
fn extract_ssl_certificate(raw_report: &Value) -> Option<SslCertificateSummary> {
    let cert = raw_report["last_https_certificate"].clone();

    Some(SslCertificateSummary {
        issuer: cert["issuer"]["CN"].as_str().unwrap_or_default().to_string(),
        validity_start: cert["validity"]["not_before"].as_str().unwrap_or_default().to_string(),
        validity_end: cert["validity"]["not_after"].as_str().unwrap_or_default().to_string(),
        key_type: cert["public_key"]["algorithm"].as_str().unwrap_or_default().to_string(),
        key_size: cert["public_key"]["rsa"]["key_size"].as_u64().unwrap_or_default() as u32,
        alternative_names: cert["subject_alternative_name"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
    })
}