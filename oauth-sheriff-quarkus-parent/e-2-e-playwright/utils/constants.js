/**
 * @fileoverview Constants for OAuth Sheriff Dev-UI E2E tests
 */

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || "https://localhost:8443";
const KEYCLOAK_URL =
    process.env.PLAYWRIGHT_KEYCLOAK_URL || "https://localhost:1443";

export const CONSTANTS = {
    URLS: {
        BASE: BASE_URL,
        DEVUI: `${BASE_URL}/q/dev-ui/`,
        DEVUI_EXTENSIONS: `${BASE_URL}/q/dev-ui/extensions`,
        HEALTH: `${BASE_URL}/q/health`,
        HEALTH_READY: `${BASE_URL}/q/health/ready`,
        KEYCLOAK: KEYCLOAK_URL,
        KEYCLOAK_TOKEN: `${KEYCLOAK_URL}/realms/benchmark/protocol/openid-connect/token`,
        KEYCLOAK_INTEGRATION_TOKEN: `${KEYCLOAK_URL}/realms/integration/protocol/openid-connect/token`,
    },

    /** Dev-UI navigation paths for OAuth Sheriff extension pages.
     *  Namespace is the Maven artifactId; slugs are derived from page titles. */
    DEVUI_PAGES: {
        VALIDATION_STATUS: `${BASE_URL}/q/dev-ui/oauth-sheriff-quarkus/jwt-validation-status`,
        JWKS_ENDPOINTS: `${BASE_URL}/q/dev-ui/oauth-sheriff-quarkus/jwks-endpoints`,
        TOKEN_DEBUGGER: `${BASE_URL}/q/dev-ui/oauth-sheriff-quarkus/token-debugger`,
        CONFIGURATION: `${BASE_URL}/q/dev-ui/oauth-sheriff-quarkus/configuration`,
    },

    /** data-testid selectors for Playwright locators */
    SELECTORS: {
        // Validation Status
        VALIDATION_STATUS_CARD: '[data-testid="validation-status-card"]',
        VALIDATION_STATUS_INDICATOR:
            '[data-testid="validation-status-indicator"]',
        VALIDATION_STATUS_MESSAGE: '[data-testid="validation-status-message"]',
        METRIC_ENABLED: '[data-testid="metric-enabled"]',
        METRIC_VALIDATOR_PRESENT: '[data-testid="metric-validator-present"]',
        METRIC_OVERALL_STATUS: '[data-testid="metric-overall-status"]',
        VALIDATION_REFRESH_BUTTON: '[data-testid="validation-refresh-button"]',
        VALIDATION_LOADING: '[data-testid="validation-loading"]',
        VALIDATION_ERROR: '[data-testid="validation-error"]',

        // JWKS Endpoints
        JWKS_ENDPOINTS_CONTAINER: '[data-testid="jwks-endpoints-container"]',
        JWKS_STATUS_MESSAGE: '[data-testid="jwks-status-message"]',
        JWKS_REFRESH_BUTTON: '[data-testid="jwks-refresh-button"]',
        JWKS_ISSUER_CARD: '[data-testid="jwks-issuer-card"]',
        JWKS_LOADING: '[data-testid="jwks-loading"]',
        JWKS_ERROR: '[data-testid="jwks-error"]',

        // Token Debugger
        JWT_DEBUGGER_CONTAINER: '[data-testid="jwt-debugger-container"]',
        JWT_DEBUGGER_TOKEN_INPUT: '[data-testid="jwt-debugger-token-input"]',
        JWT_DEBUGGER_VALIDATE_BUTTON:
            '[data-testid="jwt-debugger-validate-button"]',
        JWT_DEBUGGER_CLEAR_BUTTON: '[data-testid="jwt-debugger-clear-button"]',
        JWT_DEBUGGER_SAMPLE_BUTTON:
            '[data-testid="jwt-debugger-sample-button"]',
        JWT_DEBUGGER_RESULT: '[data-testid="jwt-debugger-result"]',
        JWT_DEBUGGER_RESULT_TITLE: '[data-testid="jwt-debugger-result-title"]',
        JWT_DEBUGGER_CLAIMS: '[data-testid="jwt-debugger-claims"]',

        // Configuration
        JWT_CONFIG_CONTAINER: '[data-testid="jwt-config-container"]',
        JWT_CONFIG_HEALTH_INDICATOR:
            '[data-testid="jwt-config-health-indicator"]',
        JWT_CONFIG_REFRESH_BUTTON: '[data-testid="jwt-config-refresh-button"]',
        JWT_CONFIG_GENERAL_SECTION:
            '[data-testid="jwt-config-general-section"]',
        JWT_CONFIG_PARSER_SECTION: '[data-testid="jwt-config-parser-section"]',
        JWT_CONFIG_ISSUERS_SECTION:
            '[data-testid="jwt-config-issuers-section"]',
        JWT_CONFIG_LOADING: '[data-testid="jwt-config-loading"]',
        JWT_CONFIG_ERROR: '[data-testid="jwt-config-error"]',
    },

    /** Keycloak authentication credentials */
    AUTH: {
        BENCHMARK: {
            CLIENT_ID: "benchmark-client",
            CLIENT_SECRET: "benchmark-secret",
            REALM: "benchmark",
        },
        INTEGRATION: {
            CLIENT_ID: "integration-client",
            CLIENT_SECRET: "integration-secret",
            REALM: "integration",
        },
    },

    /** Timeouts */
    TIMEOUTS: {
        NAVIGATION: 30_000,
        ELEMENT_VISIBLE: 15_000,
        JSON_RPC: 10_000,
        SHORT: 5_000,
    },
};
