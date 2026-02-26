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
package de.cuioss.benchmarking.common.config;

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Integration.Properties;
import static de.cuioss.benchmarking.common.repository.TokenRepositoryConfig.requireProperty;

/**
 * Configuration for integration benchmark scenarios.
 * Handles URLs and connection details for external services used in integration testing.
 * 
 * <p>Example usage:
 * <pre>{@code
 * var integrationConfig = IntegrationConfiguration.fromProperties();
 * String serviceUrl = integrationConfig.integrationServiceUrl();
 * }</pre>
 * 
 */
public record IntegrationConfiguration(
String integrationServiceUrl,
String keycloakUrl,
String metricsUrl
) {


    /**
     * Creates integration configuration from system properties.
     * All integration URLs are required for integration benchmarks to work properly.
     * 
     * @return IntegrationConfiguration with values from properties
     * @throws IllegalArgumentException if any required property is missing
     */
    public static IntegrationConfiguration fromProperties() {
        return new IntegrationConfiguration(
                requireProperty(System.getProperty(Properties.INTEGRATION_SERVICE_URL),
                        "Integration service URL", Properties.INTEGRATION_SERVICE_URL),
                requireProperty(System.getProperty(Properties.KEYCLOAK_URL),
                        "Keycloak URL", Properties.KEYCLOAK_URL),
                requireProperty(System.getProperty(Properties.METRICS_URL),
                        "Metrics URL", Properties.METRICS_URL)
        );
    }

    /**
     * Builder for IntegrationConfiguration.
     */
    public static class Builder {
        private String integrationServiceUrl;
        private String keycloakUrl;
        private String metricsUrl;

        public Builder withIntegrationServiceUrl(String url) {
            this.integrationServiceUrl = url;
            return this;
        }

        public Builder withKeycloakUrl(String url) {
            this.keycloakUrl = url;
            return this;
        }

        public Builder withMetricsUrl(String url) {
            this.metricsUrl = url;
            return this;
        }

        public IntegrationConfiguration build() {
            return new IntegrationConfiguration(
                    requireProperty(integrationServiceUrl,
                            "Integration service URL", Properties.INTEGRATION_SERVICE_URL),
                    requireProperty(keycloakUrl,
                            "Keycloak URL", Properties.KEYCLOAK_URL),
                    requireProperty(metricsUrl,
                            "Metrics URL", Properties.METRICS_URL)
            );
        }
    }

    /**
     * Creates a builder for IntegrationConfiguration.
     * 
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }
}