use super::stacks;
use crate::{Severity, TargetInfo};

pub fn get_api_exposure_checks(info: &TargetInfo) -> Vec<(&'static str, Severity)> {
    let id = stacks::identify(info);
    let mut checks = vec![
        // Critical: debug endpoints that should never be public
        ("/debug/pprof", Severity::High),
        ("/debug/vars", Severity::High),
        ("/debug", Severity::High),
        // High: admin, internal, private endpoints
        ("/api/admin", Severity::High),
        ("/api/internal", Severity::High),
        ("/api/private", Severity::High),
        ("/api/debug", Severity::High),
        ("/api/config", Severity::High),
        ("/api/settings", Severity::High),
        ("/api/env", Severity::High),
        ("/env", Severity::High),
        ("/config", Severity::High),
        // Medium: documentation, introspection, management
        ("/actuator", Severity::Medium),
        ("/actuator/health", Severity::Medium),
        ("/swagger", Severity::Medium),
        ("/swagger-ui", Severity::Medium),
        ("/swagger-ui.html", Severity::Medium),
        ("/swagger.json", Severity::Medium),
        ("/swagger/v1/swagger.json", Severity::Medium),
        ("/api-docs", Severity::Medium),
        ("/graphiql", Severity::Medium),
        ("/altair", Severity::Medium),
        ("/api/graphql/playground", Severity::Medium),
        ("/api/schema", Severity::Medium),
        ("/metrics", Severity::Medium),
        ("/prometheus", Severity::Medium),
        ("/console", Severity::Medium),
        ("/wp-json/wp/v2/users", Severity::Medium),
        ("/.well-known/openid-configuration", Severity::Medium),
        ("/trace", Severity::Medium),
        // Low: standard API paths and discovery
        ("/api", Severity::Low),
        ("/api/v1", Severity::Low),
        ("/api/v2", Severity::Low),
        ("/api/v3", Severity::Low),
        ("/api/v4", Severity::Low),
        ("/graphql", Severity::Low),
        ("/wp-json", Severity::Low),
        ("/sitemap.xml", Severity::Low),
        ("/crossdomain.xml", Severity::Low),
        ("/clientaccesspolicy.xml", Severity::Low),
        ("/.well-known/security.txt", Severity::Low),
        // Info: health/status (expected to be public)
        ("/health", Severity::Info),
        ("/healthz", Severity::Info),
        ("/readyz", Severity::Info),
        ("/livez", Severity::Info),
        ("/status", Severity::Info),
        ("/info", Severity::Info),
        ("/version", Severity::Info),
    ];
    if id.spring {
        checks.extend([
            ("/actuator/env", Severity::Medium),
            ("/actuator/beans", Severity::Medium),
            ("/actuator/mappings", Severity::Medium),
            ("/actuator/configprops", Severity::Medium),
        ]);
    }
    if id.fastapi {
        checks.extend([
            ("/openapi", Severity::Medium),
            ("/openapi.json", Severity::Medium),
            ("/openapi.yaml", Severity::Medium),
            ("/docs", Severity::Medium),
            ("/redoc", Severity::Medium),
        ]);
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_paths_follow_the_fingerprint() {
        let plain = get_api_exposure_checks(&TargetInfo::default());
        assert!(!plain.iter().any(|(path, _)| *path == "/actuator/env"));
        assert!(!plain.iter().any(|(path, _)| *path == "/docs"));
        assert!(!plain.iter().any(|(path, _)| *path == "/openapi.json"));
        assert!(plain.iter().any(|(path, _)| *path == "/debug/pprof"));
        assert!(plain.iter().any(|(path, _)| *path == "/actuator/health"));

        let spring = TargetInfo {
            technologies: vec!["Spring".to_string()],
            ..Default::default()
        };
        let spring_paths = get_api_exposure_checks(&spring);
        assert!(spring_paths
            .iter()
            .any(|(path, _)| *path == "/actuator/env"));
        assert!(!spring_paths
            .iter()
            .any(|(path, _)| *path == "/actuator/heapdump"));

        let fastapi = TargetInfo {
            technologies: vec!["Uvicorn".to_string()],
            ..Default::default()
        };
        let docs = get_api_exposure_checks(&fastapi);
        assert!(docs.iter().any(|(path, _)| *path == "/docs"));
        assert!(docs.iter().any(|(path, _)| *path == "/redoc"));
        assert!(docs.iter().any(|(path, _)| *path == "/openapi.json"));
    }
}
