use super::*;

#[test]
fn scan_filter_keeps_findings_under_their_titles() {
    let report = "// urls (2)\nhttps://api.example.com/v1\nhttps://cdn.other.net/x\n// secrets (1)\nAIzaExampleKey\n// http calls\nokhttp3.OkHttpClient\n";
    assert_eq!(
        scan_lines(report, Some("EXAMPLE")),
        vec![
            "// urls (2)",
            "https://api.example.com/v1",
            "// secrets (1)",
            "AIzaExampleKey"
        ]
    );
    // no filter: every line, for paging
    assert_eq!(scan_lines(report, None).len(), 7);
    assert_eq!(scan_lines(report, Some("")).len(), 7);
}
