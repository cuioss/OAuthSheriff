/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.benchmarking.common.repository;

import lombok.Builder;
import lombok.Value;

/**
 * Configuration for TokenRepository to connect to Keycloak and fetch tokens
 * for benchmark testing.
 *
 */
@Value
@Builder
public class TokenRepositoryConfig {

    /**
     * System property keys for token repository configuration.
     */
    public static final class Properties {
        public static final String KEYCLOAK_URL = "token.keycloak.url";
        public static final String REALM = "token.keycloak.realm";
        public static final String CLIENT_ID = "token.keycloak.clientId";
        public static final String CLIENT_SECRET = "token.keycloak.clientSecret";
        public static final String USERNAME = "token.keycloak.username";
        public static final String PASSWORD = "token.keycloak.password";
        public static final String POOL_SIZE = "token.pool.size";
        public static final String CONNECTION_TIMEOUT_MS = "token.connection.timeoutMs";
        public static final String REQUEST_TIMEOUT_MS = "token.request.timeoutMs";
        public static final String VERIFY_SSL = "token.verifySsl";
        public static final String REFRESH_THRESHOLD_SECONDS = "token.refreshThresholdSeconds";

        private Properties() {
        }
    }

    /**
     * The base URL of the Keycloak server.
     * Example: https://localhost:1443
     * Required - must be provided via properties or builder.
     */
    String keycloakBaseUrl;

    /**
     * The Keycloak realm name.
     * Required - must be provided via properties or builder.
     */
    String realm;

    /**
     * The client ID for token requests.
     * Required - must be provided via properties or builder.
     */
    String clientId;

    /**
     * The client secret for token requests.
     * Required - must be provided via properties or builder.
     */
    String clientSecret;

    /**
     * The username for token requests.
     * Required - must be provided via properties or builder.
     */
    String username;

    /**
     * The password for token requests.
     * Required - must be provided via properties or builder.
     */
    String password;

    /**
     * Number of tokens to fetch and cache for rotation.
     * This should be configured to achieve approximately 10% cache hit ratio
     * based on the expected number of benchmark requests.
     * Default: 5000 (10x the default cache size of 500)
     */
    @Builder.Default
    int tokenPoolSize = 100;

    /**
     * Connection timeout in milliseconds for Keycloak requests.
     * Default: 5000ms (5 seconds)
     */
    @Builder.Default
    int connectionTimeoutMs = 5000;

    /**
     * Request timeout in milliseconds for Keycloak requests.
     * Default: 10000ms (10 seconds)
     */
    @Builder.Default
    int requestTimeoutMs = 10000;

    /**
     * Whether to verify SSL certificates when connecting to Keycloak.
     * Should be false for local testing with self-signed certificates.
     * Default: false
     */
    @Builder.Default
    boolean verifySsl = false;

    /**
     * Token refresh threshold - tokens will be refreshed when they have less
     * than this many seconds left before expiration.
     * Default: 180 seconds (3 minutes) - safe margin for 15-minute tokens
     */
    @Builder.Default
    int tokenRefreshThresholdSeconds = 180;

    /**
     * Creates a configuration from system properties.
     * All required properties must be provided via system properties or Maven -D arguments.
     * 
     * @return TokenRepositoryConfig with values from properties
     * @throws IllegalArgumentException if any required property is missing
     */
    public static TokenRepositoryConfig fromProperties() {
        return TokenRepositoryConfig.builder()
                .keycloakBaseUrl(requireProperty(System.getProperty(Properties.KEYCLOAK_URL), "Keycloak URL", Properties.KEYCLOAK_URL))
                .realm(requireProperty(System.getProperty(Properties.REALM), "Keycloak realm", Properties.REALM))
                .clientId(requireProperty(System.getProperty(Properties.CLIENT_ID), "Client ID", Properties.CLIENT_ID))
                .clientSecret(requireProperty(System.getProperty(Properties.CLIENT_SECRET), "Client secret", Properties.CLIENT_SECRET))
                .username(requireProperty(System.getProperty(Properties.USERNAME), "Username", Properties.USERNAME))
                .password(requireProperty(System.getProperty(Properties.PASSWORD), "Password", Properties.PASSWORD))
                .tokenPoolSize(Integer.parseInt(System.getProperty(Properties.POOL_SIZE, "100")))
                .connectionTimeoutMs(Integer.parseInt(System.getProperty(Properties.CONNECTION_TIMEOUT_MS, "5000")))
                .requestTimeoutMs(Integer.parseInt(System.getProperty(Properties.REQUEST_TIMEOUT_MS, "10000")))
                .verifySsl(Boolean.parseBoolean(System.getProperty(Properties.VERIFY_SSL, "false")))
                .tokenRefreshThresholdSeconds(Integer.parseInt(System.getProperty(Properties.REFRESH_THRESHOLD_SECONDS, "180")))
                .build();
    }

    /**
     * Validates that a system property is not null or empty.
     * 
     * @param value the property value to check
     * @param description human-readable description of what the property represents
     * @param propertyName the system property name
     * @return the validated value
     * @throws IllegalArgumentException if the value is null or empty
     */
    public static String requireProperty(String value, String description, String propertyName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("%s is required but not provided. Set system property: %s".formatted(
                    description, propertyName));
        }
        return value;
    }
}