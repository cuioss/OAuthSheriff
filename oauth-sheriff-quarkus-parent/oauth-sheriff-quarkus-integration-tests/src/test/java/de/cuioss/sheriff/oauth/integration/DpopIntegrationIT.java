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

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Integration tests for RFC 9449 DPoP (Demonstrating Proof of Possession) support.
 * <p>
 * Tests DPoP sender-constrained token validation against a real Keycloak instance
 * via the full Docker Compose stack. Uses the integration realm with
 * {@code dpop.bound.access.tokens=true} on the client.
 * <p>
 * Authorization scheme: Uses {@code Authorization: Bearer <token>} even for DPoP-bound
 * tokens (existing design — the DPoP proof is validated when the {@code DPoP} header
 * and {@code cnf.jkt} claim are present).
 */
@DisplayName("DPoP Integration Tests (RFC 9449)")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DpopIntegrationIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(DpopIntegrationIT.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String JWT_VALIDATE_PATH = "/jwt/validate";
    private static final String AUTHORIZATION = "Authorization";

    private final TestRealm dpopRealm = TestRealm.createDpopRealm();
    private final TestRealm integrationRealm = TestRealm.createIntegrationRealm();

    // === Positive Tests ===

    @Test
    @Order(1)
    @DisplayName("Should obtain DPoP-bound token from Keycloak")
    void shouldObtainDpopBoundToken() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        assertNotNull(tokenResponse.accessToken(), "DPoP-bound access token should not be null");
        LOGGER.info("Successfully obtained DPoP-bound token from Keycloak dpop-client");
    }

    @Test
    @Order(2)
    @DisplayName("Should validate DPoP-bound token with valid DPoP proof")
    void shouldValidateDpopBoundToken() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();
        String resourceProof = dpopHelper.createResourceProof(accessToken);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", resourceProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Access token is valid"));
    }

    @Test
    @Order(3)
    @DisplayName("Should validate multiple requests with fresh DPoP proofs")
    void shouldValidateMultipleRequestsWithFreshProofs() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        for (int i = 0; i < 3; i++) {
            String freshProof = dpopHelper.createResourceProof(accessToken);
            given()
                    .contentType("application/json")
                    .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                    .header("DPoP", freshProof)
                    .when()
                    .post(JWT_VALIDATE_PATH)
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true));
        }
    }

    @Test
    @Order(4)
    @DisplayName("Should still accept bearer token without DPoP (dpop.required=false)")
    void shouldStillAcceptBearerTokenWithoutDpop() {
        // Regular token from integration-client (no DPoP) — works since dpop.required=false
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

    // === Negative Tests ===

    @Test
    @Order(10)
    @DisplayName("Should reject DPoP-bound token without DPoP header")
    void shouldRejectDpopTokenWithoutDpopHeader() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);

        // Token has cnf.jkt but no DPoP header — must be rejected
        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @Test
    @Order(11)
    @DisplayName("Should reject DPoP proof signed with wrong key")
    void shouldRejectDpopTokenWithWrongKey() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        // Create proof with a DIFFERENT key pair — thumbprint won't match cnf.jkt
        var wrongKeyHelper = DpopProofHelper.createWithDifferentKey();
        String wrongProof = wrongKeyHelper.createResourceProof(accessToken);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", wrongProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @Test
    @Order(12)
    @DisplayName("Should reject replayed DPoP proof (same jti)")
    void shouldRejectReplayedDpopProof() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        String fixedJti = "replay-test-" + System.currentTimeMillis();
        String proof = dpopHelper.createResourceProofWithJti(accessToken, fixedJti);

        // First request — should succeed
        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", proof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200);

        // Second request with same proof (same jti) — should be rejected
        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", proof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @Test
    @Order(13)
    @DisplayName("Should reject stale DPoP proof (iat too old)")
    void shouldRejectStaleDpopProof() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        // Create proof with iat 10 minutes in the past (max age is 300s)
        long staleIat = (System.currentTimeMillis() / 1000) - 600;
        String staleProof = dpopHelper.createResourceProofWithIat(accessToken, staleIat);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", staleProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @Test
    @Order(14)
    @DisplayName("Should reject DPoP proof with wrong ath (access token hash mismatch)")
    void shouldRejectDpopProofWithWrongAth() {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = dpopRealm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        // Create proof with ath computed from a different token
        String wrongAth = "dGhpc19pc19hX3dyb25nX2F0aF92YWx1ZQ";
        String wrongAthProof = dpopHelper.createResourceProofWithAth(wrongAth);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", wrongAthProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }
}
