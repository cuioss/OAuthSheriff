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
package de.cuioss.benchmarking.common.token;

/**
 * Common interface for providing JWT tokens for benchmark testing.
 * <p>
 * This interface abstracts the token provisioning mechanism, allowing for different
 * implementations depending on the benchmark requirements:
 * <ul>
 *   <li>{@code MockTokenRepository} - Generates tokens in-memory for isolated library benchmarks</li>
 *   <li>{@code KeycloakTokenRepository} - Fetches real tokens from Keycloak for integration benchmarks</li>
 * </ul>
 * <p>
 * Implementations should provide efficient token rotation to simulate realistic usage patterns
 * and ensure proper cache miss scenarios during benchmarking.
 * </p>
 *
 * @author Oliver Wolff
 */
public interface TokenProvider {

    /**
     * Gets the next token from the provider.
     * <p>
     * Implementations should provide round-robin or similar rotation strategy
     * to ensure even distribution of tokens and realistic cache behavior.
     * </p>
     *
     * @return a valid JWT access token
     * @throws RuntimeException if a token cannot be provided
     */
    String getNextToken();

    /**
     * Returns the current size of the token pool.
     * <p>
     * This method is useful for monitoring and capacity planning during benchmarks.
     * </p>
     *
     * @return the number of tokens currently available in the pool
     */
    int getTokenPoolSize();

    /**
     * Refreshes the token pool with new tokens.
     * <p>
     * This method allows for token renewal during long-running benchmarks.
     * Implementations may choose to:
     * <ul>
     *   <li>Generate new tokens (mock implementations)</li>
     *   <li>Fetch fresh tokens from authentication server (real implementations)</li>
     *   <li>Do nothing if token refresh is not supported</li>
     * </ul>
     *
     * @throws RuntimeException if the refresh operation fails
     */
    void refreshTokens();
}