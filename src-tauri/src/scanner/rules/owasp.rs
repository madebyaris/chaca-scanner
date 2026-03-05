pub fn get_owasp_categories() -> Vec<&'static str> {
    vec![
        "API1:2023 - Broken Object Level Authorization",
        "API2:2023 - Broken Authentication",
        "API3:2023 - Broken Object Property Level Authorization",
        "API4:2023 - Unrestricted Resource Consumption",
        "API5:2023 - Broken Function Level Authorization",
        "API6:2023 - Unrestricted Access to Sensitive Business Flows",
        "API7:2023 - Server-Side Request Forgery",
        "API8:2023 - Security Misconfiguration",
        "API9:2023 - Improper Inventory Management",
        "API10:2023 - Unsafe Consumption of API",
    ]
}
