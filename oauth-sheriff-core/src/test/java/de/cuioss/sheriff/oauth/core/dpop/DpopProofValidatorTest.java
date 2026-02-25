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
package de.cuioss.sheriff.oauth.core.dpop;

import de.cuioss.sheriff.oauth.core.IssuerConfig;
import de.cuioss.sheriff.oauth.core.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.oauth.core.exception.TokenValidationException;
import de.cuioss.sheriff.oauth.core.json.JwtHeader;
import de.cuioss.sheriff.oauth.core.json.MapRepresentation;
import de.cuioss.sheriff.oauth.core.pipeline.DecodedJwt;
import de.cuioss.sheriff.oauth.core.security.SecurityEventCounter;
import de.cuioss.sheriff.oauth.core.security.SecurityEventCounter.EventType;
import de.cuioss.sheriff.oauth.core.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.oauth.core.util.JwkThumbprintUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class DpopProofValidatorTest {

    private static final String TEST_ISSUER = "https://test-issuer.example.com";

    private SecurityEventCounter securityEventCounter;
    private DpopReplayProtection replayProtection;
    private DpopProofValidator validator;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        replayProtection = new DpopReplayProtection(300, 10_000);

        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();

        validator = new DpopProofValidator(issuerConfig, securityEventCounter, replayProtection);
    }

    @AfterEach
    void tearDown() {
        replayProtection.close();
    }

    // === Happy Path Tests ===

    @Test
    void shouldPassWhenNoDpopHeaderAndNotRequiredAndNoCnfJkt() {
        // Bearer mode: no DPoP header, not required, no cnf.jkt in access token
        DecodedJwt accessToken = createAccessTokenJwt(null); // no cnf.jkt
        AccessTokenRequest request = new AccessTokenRequest("dummy-token", Map.of());

        assertDoesNotThrow(() -> validator.validate(request, accessToken, "dummy-token"));
    }

    @Test
    void shouldPassWithValidDpopProof() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        String dpopProof = buildDpopProof(keyPair, jwkMap, "RS256", rawAccessToken);

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
    }

    // === Rejection Tests ===

    @Test
    void shouldRejectWhenDpopRequiredButNoCnfJkt() {
        IssuerConfig requiredConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().required(true).build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        var requiredValidator = new DpopProofValidator(requiredConfig, securityEventCounter, replayProtection);

        DecodedJwt accessToken = createAccessTokenJwt(null); // no cnf.jkt
        AccessTokenRequest request = new AccessTokenRequest("dummy-token", Map.of());

        var ex = assertThrows(TokenValidationException.class,
                () -> requiredValidator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_CNF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectWhenCnfJktPresentButNoDpopHeader() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = new AccessTokenRequest("dummy-token", Map.of());

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectWhenDpopHeaderPresentButNoCnfJkt() {
        DecodedJwt accessToken = createAccessTokenJwt(null);
        AccessTokenRequest request = new AccessTokenRequest("dummy-token",
                Map.of("dpop", List.of("some.dpop.proof")));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_CNF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectInvalidDpopProofFormat() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = new AccessTokenRequest("dummy-token",
                Map.of("dpop", List.of("not-a-jwt")));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
    }

    @Test
    void shouldRejectWrongTypHeader() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with wrong typ
        String dpopProof = buildDpopProofWithCustomTyp(keyPair, jwkMap, "RS256", rawAccessToken, "jwt");

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
    }

    @Test
    void shouldRejectReplayedJti() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Use the same jti twice
        String fixedJti = UUID.randomUUID().toString();
        String dpopProof1 = buildDpopProofWithJti(keyPair, jwkMap, "RS256", rawAccessToken, fixedJti);
        String dpopProof2 = buildDpopProofWithJti(keyPair, jwkMap, "RS256", rawAccessToken, fixedJti);

        AccessTokenRequest request1 = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof1)));
        AccessTokenRequest request2 = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof2)));

        // First should pass
        assertDoesNotThrow(() -> validator.validate(request1, accessToken, rawAccessToken));

        // Second should fail (replay)
        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request2, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_REPLAY_DETECTED, ex.getEventType());
    }

    @Test
    void shouldRejectExpiredIat() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with iat 10 minutes in the past (exceeds default 300s max age)
        long staleIat = (System.currentTimeMillis() / 1000) - 600;
        String dpopProof = buildDpopProofWithIat(keyPair, jwkMap, "RS256", rawAccessToken, staleIat);

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_EXPIRED, ex.getEventType());
    }

    @Test
    void shouldRejectWrongAth() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with ath for a different token
        String dpopProof = buildDpopProofWithAth(keyPair, jwkMap, "RS256", "different.access.token");

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_ATH_MISMATCH, ex.getEventType());
    }

    @Test
    void shouldRejectThumbprintMismatch() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());

        String rawAccessToken = "some.access.token";
        // Use a different thumbprint in the access token
        DecodedJwt accessToken = createAccessTokenJwt("wrong-thumbprint-value");

        String dpopProof = buildDpopProof(keyPair, jwkMap, "RS256", rawAccessToken);

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_THUMBPRINT_MISMATCH, ex.getEventType());
    }

    @Test
    void shouldRejectInvalidSignature() {
        KeyPair keyPairForHeader = generateRsaKeyPair();
        KeyPair keyPairForSigning = generateRsaKeyPair(); // Different key!
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPairForHeader.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with header JWK from one key but signed with different key
        String dpopProof = buildDpopProofWithMismatchedKey(keyPairForSigning, jwkMap, "RS256", rawAccessToken);

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
    }

    @Test
    void shouldRejectMultipleDpopHeaders() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = new AccessTokenRequest("dummy-token",
                Map.of("dpop", List.of("proof1", "proof2")));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
        assertTrue(ex.getMessage().contains("Multiple DPoP headers"));
    }

    @Test
    void shouldRejectOversizedDpopProof() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        // Create a proof string larger than 8192 bytes
        String oversizedProof = "a".repeat(8193);
        AccessTokenRequest request = new AccessTokenRequest("dummy-token",
                Map.of("dpop", List.of(oversizedProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
        assertTrue(ex.getMessage().contains("maximum size"));
    }

    @Test
    void shouldRejectWhenDpopRequiredWithCnfJktButNoDpopHeader() {
        IssuerConfig requiredConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().required(true).build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        var requiredValidator = new DpopProofValidator(requiredConfig, securityEventCounter, replayProtection);

        // Required mode, access token has cnf.jkt but no DPoP header
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = new AccessTokenRequest("dummy-token", Map.of());

        var ex = assertThrows(TokenValidationException.class,
                () -> requiredValidator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectFutureIat() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with iat 2 minutes in the future (exceeds -60s tolerance)
        long futureIat = (System.currentTimeMillis() / 1000) + 120;
        String dpopProof = buildDpopProofWithIat(keyPair, jwkMap, "RS256", rawAccessToken, futureIat);

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_EXPIRED, ex.getEventType());
    }

    @Test
    void shouldAcceptCaseInsensitiveTyp() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Use uppercase typ
        String dpopProof = buildDpopProofWithCustomTyp(keyPair, jwkMap, "RS256", rawAccessToken, "DPoP+JWT");

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
    }

    // === Helper Methods ===

    private DecodedJwt createAccessTokenJwt(String cnfJkt) {
        Map<String, Object> bodyMap = new HashMap<>();
        bodyMap.put("iss", TEST_ISSUER);
        bodyMap.put("sub", "test-subject");
        bodyMap.put("exp", (System.currentTimeMillis() / 1000) + 3600);
        bodyMap.put("iat", System.currentTimeMillis() / 1000);
        if (cnfJkt != null) {
            bodyMap.put("cnf", Map.of("jkt", cnfJkt));
        }

        var body = new MapRepresentation(bodyMap);
        var header = new JwtHeader(
                "RS256", null, "default-key-id", null, null, null, null, null, null, null, null);

        return new DecodedJwt(header, body, "dummy-sig", new String[]{"a", "b", "c"}, "a.b.c");
    }

    private String buildDpopProof(KeyPair keyPair, Map<String, Object> jwkMap, String alg, String accessToken) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken));
    }

    private String buildDpopProofWithCustomTyp(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, String typ) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, typ,
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken));
    }

    private String buildDpopProofWithJti(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, String jti) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                jti, System.currentTimeMillis() / 1000, computeAth(accessToken));
    }

    private String buildDpopProofWithIat(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, long iat) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), iat, computeAth(accessToken));
    }

    private String buildDpopProofWithAth(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessTokenForAth) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessTokenForAth));
    }

    private String buildDpopProofWithMismatchedKey(KeyPair signingKeyPair, Map<String, Object> headerJwkMap,
            String alg, String accessToken) {
        return buildDpopProofInternal(signingKeyPair, headerJwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken));
    }

    private String buildDpopProofInternal(KeyPair signingKeyPair, Map<String, Object> headerJwkMap,
            String alg, String typ,
            String jti, long iat, String ath) {
        // Build header JSON
        String jwkJson = mapToJson(headerJwkMap);
        String headerJson = """
                {"typ":"%s","alg":"%s","jwk":%s}""".formatted(typ, alg, jwkJson);

        // Build body JSON
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s"}""".formatted(jti, iat, ath);

        // Encode
        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));

        String dataToSign = encodedHeader + "." + encodedBody;

        // Sign
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(signingKeyPair.getPrivate());
            signer.update(dataToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();

            String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);

            return dataToSign + "." + encodedSignature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }

    private String computeAth(String accessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String mapToJson(Map<String, Object> map) {
        var sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(entry.getKey()).append("\":\"").append(entry.getValue()).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }

    private Map<String, Object> rsaPublicKeyToJwkMap(RSAPublicKey publicKey) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "RSA");
        map.put("n", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(publicKey.getModulus())));
        map.put("e", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(publicKey.getPublicExponent())));
        return map;
    }

    private byte[] toUnsignedBytes(BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
