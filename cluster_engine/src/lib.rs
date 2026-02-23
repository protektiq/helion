//! Cluster engine: group normalized findings by SCA (CVE+dependency) or SAST (rule+path).
//! Input: JSON array of normalized findings with `id`. Output: JSON with clusters and metrics.

use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Input finding: same shape as NormalizedFinding plus required `id` for finding_ids.
/// When `deterministic_signature` is present (Layer A from Python), it is used as the cluster key;
/// otherwise the engine computes the key from vulnerability_id/dependency/file_path (legacy).
#[derive(Debug, Clone, Deserialize)]
pub struct NormalizedFindingInput {
    pub id: FindingId,
    pub vulnerability_id: String,
    pub severity: String,
    pub repo: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub dependency: String,
    pub cvss_score: f64,
    pub description: String,
    /// Optional precomputed cluster key (e.g. from cluster_signature); when set, used for grouping.
    #[serde(default)]
    pub deterministic_signature: Option<String>,
}

/// Accept id as string or number from JSON.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FindingId {
    Num(i64),
    Str(String),
}

impl FindingId {
    fn to_string(&self) -> String {
        match self {
            FindingId::Num(n) => n.to_string(),
            FindingId::Str(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityClusterOutput {
    pub vulnerability_id: String,
    pub severity: String,
    pub repo: String,
    pub file_path: String,
    pub dependency: String,
    pub cvss_score: f64,
    pub description: String,
    pub finding_ids: Vec<String>,
    pub affected_services_count: u32,
    pub finding_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionMetricsOutput {
    pub raw_finding_count: u32,
    pub cluster_count: u32,
    pub compression_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClustersOutput {
    pub clusters: Vec<VulnerabilityClusterOutput>,
    pub metrics: CompressionMetricsOutput,
}

fn is_cve_or_ghsa_like(vid: &str) -> bool {
    let vid = vid.trim();
    if vid.is_empty() {
        return false;
    }
    // CVE-YEAR-NNNNN+ (4+ digits after second hyphen); case-insensitive
    let cve = Regex::new(r"(?i)^CVE-\d{4}-\d{4,}$").unwrap();
    // GHSA-xxxx-xxxx-xxxx (4 alphanumeric groups); case-insensitive
    let ghsa = Regex::new(r"(?i)^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$").unwrap();
    cve.is_match(vid) || ghsa.is_match(vid)
}

fn file_path_pattern(repo: &str, file_path: &str) -> String {
    let path = file_path.trim().replace('\\', "/");
    if path.is_empty() {
        return String::new();
    }
    let mut path = path;
    let repo_norm = repo.trim().replace('\\', "/").trim_matches('/').to_string();
    if !repo_norm.is_empty() && (path.starts_with(&format!("{}/", repo_norm)) || path == repo_norm) {
        if path == repo_norm {
            path = String::new();
        } else {
            path = path[repo_norm.len() + 1..].trim_start_matches('/').to_string();
        }
    }
    path
}

fn cluster_key(f: &NormalizedFindingInput) -> String {
    let vid = f.vulnerability_id.trim();
    let dep = f.dependency.trim();
    if is_cve_or_ghsa_like(vid) {
        return format!("{}\0{}", vid, dep);
    }
    let pattern = file_path_pattern(&f.repo, &f.file_path);
    format!("{}\0{}", vid, pattern)
}

const SEVERITY_ORDER: [&str; 5] = ["info", "low", "medium", "high", "critical"];

fn severity_rank(s: &str) -> usize {
    let normalized: String = s
        .trim()
        .chars()
        .map(|c| {
            if c >= 'A' && c <= 'Z' {
                ((c as u8).wrapping_add(32)) as char
            } else {
                c
            }
        })
        .collect();
    SEVERITY_ORDER
        .iter()
        .position(|&x| x == normalized)
        .unwrap_or(0)
}

fn worst_severity(severities: &[String]) -> String {
    let mut worst_rank = 0usize;
    for s in severities {
        let r = severity_rank(s);
        if r > worst_rank {
            worst_rank = r;
        }
    }
    SEVERITY_ORDER[worst_rank].to_string()
}

/// Core clustering: group by cluster_key, then build one cluster per group.
pub fn cluster_findings(findings: &[NormalizedFindingInput]) -> ClustersOutput {
    if findings.is_empty() {
        return ClustersOutput {
            clusters: vec![],
            metrics: CompressionMetricsOutput {
                raw_finding_count: 0,
                cluster_count: 0,
                compression_ratio: 0.0,
            },
        };
    }

    // Single-threaded grouping: use precomputed deterministic_signature when present, else legacy key.
    let mut groups: HashMap<String, Vec<&NormalizedFindingInput>> = HashMap::new();
    for f in findings {
        let key: String = f
            .deterministic_signature
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| cluster_key(f));
        groups.entry(key).or_default().push(f);
    }

    let clusters: Vec<VulnerabilityClusterOutput> = groups
        .into_iter()
        .map(|(_key, group)| {
            let first = group[0];
            let finding_ids: Vec<String> = group.iter().map(|f| f.id.to_string()).collect();
            let distinct_repos: std::collections::HashSet<_> =
                group.iter().map(|f| f.repo.trim().to_string()).collect();
            let distinct_repos_count = distinct_repos.len() as u32;
            let severities: Vec<String> = group
                .iter()
                .map(|f| f.severity.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();
            let canonical_severity = if severities.is_empty() {
                "info".to_string()
            } else {
                worst_severity(&severities)
            };
            let canonical_repo = if distinct_repos_count > 1 {
                "multiple".to_string()
            } else {
                first.repo.trim().to_owned()
            };
            let canonical_repo = if canonical_repo.is_empty() {
                "unknown".to_string()
            } else {
                canonical_repo
            };
            let vuln_id = first.vulnerability_id.trim();
            let vuln_id = if vuln_id.is_empty() {
                "unknown"
            } else {
                vuln_id
            };
            VulnerabilityClusterOutput {
                vulnerability_id: vuln_id.to_string(),
                severity: canonical_severity,
                repo: canonical_repo,
                file_path: first.file_path.trim().to_owned(),
                dependency: first.dependency.trim().to_owned(),
                cvss_score: first.cvss_score,
                description: if first.description.trim().is_empty() {
                    "No description".to_string()
                } else {
                    first.description.trim().to_owned()
                },
                finding_ids: finding_ids.clone(),
                affected_services_count: distinct_repos_count.max(1),
                finding_count: finding_ids.len() as u32,
            }
        })
        .collect();

    let raw_count = findings.len() as u32;
    let cluster_count = clusters.len() as u32;
    let compression_ratio = if cluster_count > 0 {
        raw_count as f64 / cluster_count as f64
    } else {
        0.0
    };
    ClustersOutput {
        metrics: CompressionMetricsOutput {
            raw_finding_count: raw_count,
            cluster_count,
            compression_ratio,
        },
        clusters,
    }
}

/// Parse JSON array of findings and return JSON string of ClustersOutput.
pub fn cluster_findings_json(json_input: &str) -> Result<String, String> {
    let findings: Vec<NormalizedFindingInput> =
        serde_json::from_str(json_input).map_err(|e| e.to_string())?;
    let out = cluster_findings(&findings);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// PyO3 entrypoint: called from Python with JSON string, returns JSON string.
#[pyfunction]
fn cluster_findings_py(json_input: &str) -> PyResult<String> {
    cluster_findings_json(json_input).map_err(|e| PyValueError::new_err(e))
}

#[pymodule]
fn cluster_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cluster_findings_py, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: i64, vid: &str, dep: &str, repo: &str, file_path: &str, severity: &str) -> NormalizedFindingInput {
        NormalizedFindingInput {
            id: FindingId::Num(id),
            vulnerability_id: vid.to_string(),
            severity: severity.to_string(),
            repo: repo.to_string(),
            file_path: file_path.to_string(),
            dependency: dep.to_string(),
            cvss_score: 7.0,
            description: "Test".to_string(),
            deterministic_signature: None,
        }
    }

    #[test]
    fn test_sca_cluster_key() {
        let f = finding(1, "CVE-2024-1234", "lodash", "my-repo", "", "high");
        assert!(is_cve_or_ghsa_like(&f.vulnerability_id));
        let key = cluster_key(&f);
        assert_eq!(key, "CVE-2024-1234\0lodash");
    }

    #[test]
    fn test_sast_cluster_key() {
        let f = finding(1, "rule-123", "", "my-repo", "my-repo/src/foo.py", "medium");
        assert!(!is_cve_or_ghsa_like(&f.vulnerability_id));
        let key = cluster_key(&f);
        assert_eq!(key, "rule-123\0src/foo.py");
    }

    #[test]
    fn test_cluster_two_findings_same_key() {
        let a = finding(1, "CVE-2024-9999", "pkg", "r1", "", "high");
        let b = finding(2, "CVE-2024-9999", "pkg", "r1", "", "low");
        let out = cluster_findings(&[a, b]);
        assert_eq!(out.metrics.raw_finding_count, 2);
        assert_eq!(out.metrics.cluster_count, 1);
        assert_eq!(out.clusters[0].finding_count, 2);
        assert_eq!(out.clusters[0].severity, "high");
        assert_eq!(out.clusters[0].affected_services_count, 1);
    }

    #[test]
    fn test_cluster_two_repos() {
        let a = finding(1, "CVE-2024-1111", "dep", "repo-a", "", "high");
        let b = finding(2, "CVE-2024-1111", "dep", "repo-b", "", "high");
        let out = cluster_findings(&[a, b]);
        assert_eq!(out.metrics.cluster_count, 1);
        assert_eq!(out.clusters[0].repo, "multiple");
        assert_eq!(out.clusters[0].affected_services_count, 2);
    }

    #[test]
    fn test_json_roundtrip() {
        let json = r#"[{"id":1,"vulnerability_id":"CVE-2024-1","severity":"high","repo":"r","file_path":"","dependency":"d","cvss_score":8.0,"description":"D"}]"#;
        let out_str = cluster_findings_json(json).unwrap();
        let out: ClustersOutput = serde_json::from_str(&out_str).unwrap();
        assert_eq!(out.metrics.raw_finding_count, 1);
        assert_eq!(out.metrics.cluster_count, 1);
        assert_eq!(out.clusters[0].finding_ids, ["1"]);
    }

    #[test]
    fn test_deterministic_signature_used_as_key() {
        let mut a = finding(1, "CVE-2024-9999", "pkg-a", "r1", "", "high");
        let mut b = finding(2, "CVE-2024-9999", "pkg-b", "r1", "", "low");
        a.deterministic_signature = Some("same-cluster-key".to_string());
        b.deterministic_signature = Some("same-cluster-key".to_string());
        let out = cluster_findings(&[a, b]);
        assert_eq!(out.metrics.raw_finding_count, 2);
        assert_eq!(out.metrics.cluster_count, 1);
        assert_eq!(out.clusters[0].finding_count, 2);
    }
}
