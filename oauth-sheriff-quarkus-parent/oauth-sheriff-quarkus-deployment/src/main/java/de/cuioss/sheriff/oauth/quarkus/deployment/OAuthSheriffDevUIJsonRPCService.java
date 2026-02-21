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
package de.cuioss.sheriff.oauth.quarkus.deployment;


import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * JSON-RPC service for OAuth Sheriff DevUI.
 * <p>
 * This service provides methods for retrieving JWT validation information
 * for the DevUI components at build time.
 * <p>
 * Note: This service provides static build-time information only.
 * Runtime status will be available through actual application endpoints.
 */
public class OAuthSheriffDevUIJsonRPCService {

    public static final String BUILD_TIME = "BUILD_TIME";
    public static final String MESSAGE = "message";

    /**
     * Get build-time JWT validation information.
     *
     * @return A map containing build-time validation information
     */
   
    public Map<String, Object> getValidationStatus() {
        Map<String, Object> status = new HashMap<>();

        status.put("enabled", false);
        status.put("validatorPresent", false);
        status.put("status", BUILD_TIME);
        status.put("statusMessage", "JWT validation status will be available at runtime");

        return status;
    }

    /**
     * Get build-time JWKS endpoint information.
     *
     * @return A map containing build-time JWKS information
     */
   
    public Map<String, Object> getJwksStatus() {
        Map<String, Object> jwksInfo = new HashMap<>();

        jwksInfo.put("status", BUILD_TIME);
        jwksInfo.put(MESSAGE, "JWKS endpoint status will be available at runtime");

        return jwksInfo;
    }

    /**
     * Get build-time configuration information.
     *
     * @return A map containing build-time configuration information
     */
   
    public Map<String, Object> getConfiguration() {
        Map<String, Object> config = new HashMap<>();

        config.put("enabled", false);
        config.put("healthEnabled", false);
        config.put("buildTime", true);
        config.put(MESSAGE, "Configuration details will be available at runtime");

        return config;
    }

    /**
     * Validate a JWT token (build-time placeholder).
     *
     * @param token The JWT token to validate
     * @return A map containing validation result
     */

    public Map<String, Object> validateToken(@Nullable String token) {
        Map<String, Object> result = new HashMap<>();

        if (token == null || token.trim().isEmpty()) {
            result.put("valid", false);
            result.put("error", "Token is empty or null");
            return result;
        }

        result.put("valid", false);
        result.put("error", "Token validation not available at build time");

        return result;
    }

    /**
     * Get build-time health information.
     *
     * @return A map containing build-time health information
     */
   
    public Map<String, Object> getHealthInfo() {
        Map<String, Object> health = new HashMap<>();

        health.put("configurationValid", true);
        health.put("tokenValidatorAvailable", false);
        health.put("securityCounterAvailable", false);
        health.put("overallStatus", BUILD_TIME);
        health.put(MESSAGE, "Health information will be available at runtime");

        return health;
    }
}
