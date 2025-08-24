use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Stores the report from the Virus Total API
#[derive(Deserialize, Debug)]
struct VirusTotalResult {
    categories: Option<HashMap<String, String>>,
    first_submission_date: Option<u64>,
    last_analysis_date: Option<u64>,
    last_analysis_results: Option<HashMap<String, EngineResult>>,
    last_http_response_code: Option<u16>,
    reputation: Option<i32>,
    times_submitted: Option<u32>,
    tld: Option<String>,
    title: Option<String>,
}

// Stores engine result (ex: "Forcepoint ThreatSeeker": "search engines and portals" for https://www.google.com)
#[derive(Deserialize, Debug)]
struct EngineResult {
    category: Option<String>,
}

// Summary of the full report
#[derive(Serialize)]
struct VirusTotalSummary {
    categories: Option<HashMap<String, String>>,
    harmless_count: u32,
    undetected_count: u32,
    unrated_count: u32,
    suspicious_count: u32,
    malicious_count: u32,
    first_submission_date: Option<u64>,
    last_analysis_date: Option<u64>,
    last_http_response_code: String,
    reputation: Option<i32>,
    times_submitted: Option<u32>,
    tld: Option<String>,
    title: Option<String>,
}

/// Creates a summary with the full Virus Total report
pub fn collector(data: &String) -> Result<String, Box<dyn std::error::Error>> {
    // Parse JSON content as a single VirusTotalResult
    let vt_result: VirusTotalResult = serde_json::from_str(data)?;

    /// Counts the number of occurrence for each report (ex: malicious, suspicious, etc.)
    fn count_category(results: &Option<HashMap<String, EngineResult>>, category: &str) -> u32 {
        results
            .as_ref() // Convert Option<HashMap> to Option<&HashMap>
            .map(|map| {
                map.values() // Get all EngineResult values
                    .filter(|engine| engine.category.as_deref() == Some(category)) // Filter by category
                    .count() as u32 // Count matches
            })
            .unwrap_or(0) // Default to 0 if the Option is None
    }

    // Creates a single summary
    let summary = {

        // Transforms http code to its value
        let http_response = match vt_result.last_http_response_code {
            Some(200) => "Success (200)",
            Some(301) => "The requested resource has been permanently moved (301)",
            Some(302) => "The requested resource has been temporary moved (302)",
            Some(401) => "Access unauthorized (401)",
            Some(403) => "Access forbidden (403)",
            Some(404) => "Resource not found (404)",
            Some(500) => "Internal server error (500)",
            Some(501) => "Internal server error (501)",
            Some(503) => "Internal server error (503)",
            Some(504) => "No response (504)",
            _ => "Unknown error",
        };

        // Stores the result in the data structure
        VirusTotalSummary {
            categories: vt_result.categories.clone(),
            harmless_count: count_category(&vt_result.last_analysis_results, "harmless"),
            undetected_count: count_category(&vt_result.last_analysis_results, "undetected"),
            unrated_count: count_category(&vt_result.last_analysis_results, "unrated"),
            suspicious_count: count_category(&vt_result.last_analysis_results, "suspicious"),
            malicious_count: count_category(&vt_result.last_analysis_results, "malicious"),
            first_submission_date: vt_result.first_submission_date,
            last_analysis_date: vt_result.last_analysis_date,
            last_http_response_code: http_response.to_string(),
            reputation: vt_result.reputation,
            times_submitted: vt_result.times_submitted,
            tld: vt_result.tld.clone(),
            title: vt_result.title.clone(),
        }
    };

    // Returns the result as JSON
    Ok(serde_json::to_string_pretty(&summary)?)
}