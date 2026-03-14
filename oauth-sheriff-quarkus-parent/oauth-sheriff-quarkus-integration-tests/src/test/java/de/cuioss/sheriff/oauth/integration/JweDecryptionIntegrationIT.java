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
package de.cuioss.sheriff.oauth.integration;

import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.*;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for JWE (JSON Web Encryption) decryption per RFC 7516.
 * <p>
 * Tests JWE token decryption against a real Keycloak instance configured to encrypt
 * ID tokens for the {@code jwe-client} using RSA-OAEP + A256GCM. The Resource Server
 * decrypts the JWE with its local private key, then validates the inner JWS normally.
 * <p>
 * Keycloak encrypts <b>ID tokens</b> (not access tokens) when
 * {@code id.token.encrypted.response.alg/enc} is configured on the client. Access tokens
 * from the same client remain unencrypted (JWS), so both paths are exercised.
 */
@DisplayName("JWE Decryption Integration Tests (RFC 7516)")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JweDecryptionIntegrationIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(JweDecryptionIntegrationIT.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String JWT_VALIDATE_PATH = "/jwt/validate";
    private static final String ID_TOKEN_VALIDATE_PATH = "/jwt/validate/id-token";
    private static final String AUTHORIZATION = "Authorization";

    private final TestRealm jweRealm = TestRealm.createJweRealm();
    private final TestRealm integrationRealm = TestRealm.createIntegrationRealm();

    // === Positive Tests ===

    @Test
    @Order(1)
    @DisplayName("Should obtain tokens from JWE-enabled client")
    void shouldObtainTokensFromJweClient() {
        var tokenResponse = jweRealm.obtainValidToken();
        assertNotNull(tokenResponse.accessToken(), "Access token should not be null");
        assertNotNull(tokenResponse.idToken(), "ID token should not be null");
        LOGGER.info("Successfully obtained tokens from Keycloak jwe-client");

        // Verify ID token is JWE (5 parts) — Keycloak encrypts ID tokens
        String idToken = tokenResponse.idToken();
        int dotCount = idToken.split("\\.", -1).length - 1;
        assertEquals(4, dotCount,
                "ID token from jwe-client should be JWE (5 parts, 4 dots), got " + (dotCount + 1) + " parts");
        LOGGER.info("ID token is JWE format (5 parts) as expected");

        // Access token remains JWS (3 parts) — Keycloak doesn't encrypt access tokens
        String accessToken = tokenResponse.accessToken();
        int accessDotCount = accessToken.split("\\.", -1).length - 1;
        assertEquals(2, accessDotCount,
                "Access token should remain JWS (3 parts), got " + (accessDotCount + 1) + " parts");
    }

    @Test
    @Order(2)
    @DisplayName("Should validate JWE-encrypted ID token")
    void shouldValidateJweEncryptedIdToken() {
        var tokenResponse = jweRealm.obtainValidToken();

        given()
                .contentType("application/json")
                .body(Map.of("token", tokenResponse.idToken()))
                .when()
                .post(ID_TOKEN_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("ID token is valid"));
    }

    @Test
    @Order(3)
    @DisplayName("Should validate access token from JWE-enabled client (access token stays JWS)")
    void shouldValidateAccessTokenFromJweClient() {
        var tokenResponse = jweRealm.obtainValidToken();

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Access token is valid"));
    }

    @Test
    @Order(4)
    @DisplayName("Should still validate regular JWS tokens when JWE config is present")
    void shouldStillValidateRegularJwsTokens() {
        // Regular integration-client tokens (no encryption) should work unchanged
        var tokenResponse = integrationRealm.obtainValidToken();

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true));
    }

    @Test
    @Order(5)
    @DisplayName("Should validate JWE ID token multiple times (cache integration)")
    void shouldValidateJweIdTokenMultipleTimes() {
        var tokenResponse = jweRealm.obtainValidToken();

        for (int i = 0; i < 3; i++) {
            given()
                    .contentType("application/json")
                    .body(Map.of("token", tokenResponse.idToken()))
                    .when()
                    .post(ID_TOKEN_VALIDATE_PATH)
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true));
        }
    }

    // === Negative Tests ===

    @Test
    @Order(10)
    @DisplayName("Should reject tampered JWE token")
    void shouldRejectTamperedJweToken() {
        var tokenResponse = jweRealm.obtainValidToken();
        String idToken = tokenResponse.idToken();

        // Tamper with the ciphertext (4th part)
        String[] parts = idToken.split("\\.");
        assertEquals(5, parts.length, "Should be 5-part JWE");
        // Flip a character in the ciphertext
        char[] cipherChars = parts[3].toCharArray();
        cipherChars[0] = cipherChars[0] == 'A' ? 'B' : 'A';
        parts[3] = new String(cipherChars);
        String tamperedToken = String.join(".", parts);

        given()
                .contentType("application/json")
                .body(Map.of("token", tamperedToken))
                .when()
                .post(ID_TOKEN_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }
}
