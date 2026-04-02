use irongate::log_ingestor::parser::parse_line;
use irongate::types::RequestType;

#[test]
fn test_parse_valid_log_line() {
    let line = "[\"arsenalcraft.com.br\"] 2a03:2880:24ff:5f:: - - [02/Apr/2026:07:46:32 +0000] \"GET /p/kit-mergulhadores HTTP/1.1\" 200 9490 \"ref\" \"meta-externalads/1.1\"";
    let entry = parse_line(line).expect("Should parse successfully");

    assert_eq!(entry.vhost, "arsenalcraft.com.br");
    assert_eq!(entry.client_ip.to_string(), "2a03:2880:24ff:5f::");
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.uri, "/p/kit-mergulhadores");
    assert_eq!(entry.status, 200);
    assert_eq!(entry.size, 9490);
    assert_eq!(entry.referer, "ref");
    assert_eq!(entry.user_agent, "meta-externalads/1.1");
    assert_eq!(entry.request_type, RequestType::Page);
}

#[test]
fn test_parse_ajax_line() {
    let line = "[\"arsenalcraft.com.br\"] 192.168.1.1 - - [02/Apr/2026:07:46:32 +0000] \"POST /?wc-ajax=update_order_review HTTP/1.1\" 200 120 \"-\" \"curl/7.68.0\"";
    let entry = parse_line(line).unwrap();
    assert_eq!(entry.request_type, RequestType::Ajax);
}
