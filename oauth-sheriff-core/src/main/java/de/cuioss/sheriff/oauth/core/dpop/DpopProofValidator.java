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

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.oauth.core.IssuerConfig;
import de.cuioss.sheriff.oauth.core.JWTValidationLogMessages;
import de.cuioss.sheriff.oauth.core.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.oauth.core.exception.TokenValidationException;
import de.cuioss.sheriff.oauth.core.json.JwkKey;
import de.cuioss.sheriff.oauth.core.json.MapRepresentation;
import de.cuioss.sheriff.oauth.core.jwks.key.JwkKeyHandler;
import de.cuioss.sheriff.oauth.core.pipeline.DecodedJwt;
import de.cuioss.sheriff.oauth.core.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.oauth.core.security.SecurityEventCounter;
import de.cuioss.sheriff.oauth.core.security.SecurityEventCounter.EventType;
import de.cuioss.sheriff.oauth.core.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.oauth.core.util.EcdsaSignatureFormatConverter;
import de.cuioss.sheriff.oauth.core.util.JwkThumbprintUtil;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.logging.LogRecord;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Validates DPoP (Demonstrating Proof of Possession) proofs per RFC 9449.
 * <p>
 * This validator checks:
 * <ol>
 *   <li>Presence of the DPoP HTTP header</li>
 *   <li>Extraction of {@code cnf.jkt} from the access token</li>
 *   <li>DPoP proof JWT structure (typ, alg, jwk)</li>
 *   <li>DPoP proof signature using embedded JWK</li>
 *   <li>jti uniqueness (replay protection)</li>
 *   <li>iat freshness check</li>
 *   <li>ath (access token hash) match</li>
 *   <li>JWK Thumbprint match against cnf.jkt</li>
 * </ol>
 * <p>
 * DPoP proof JWTs are decoded manually (not via {@code NonValidatingJwtParser})
 * because the DPoP proof header contains {@code jwk} as a nested JSON object,
 * while DSL-JSON's {@code JwtHeader} expects it as a String.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449</a>
 */
public class DpopProofValidator {

    private static final CuiLogger LOGGER = new CuiLogger(DpopProofValidator.class);
    private static final String DPOP_HEADER_NAME = "dpop";
    private static final String DPOP_TYP = "dpop+jwt";
    /** Maximum DPoP proof size (8KB matches the token size limit from ParserConfig). */
    private static final int MAX_DPOP_PROOF_SIZE = 8192;

    private final DpopConfig config;
    private final SecurityEventCounter securityEventCounter;
    private final DpopReplayProtection replayProtection;
    private final SignatureAlgorithmPreferences algorithmPreferences;
    private final DslJson<Object> dslJson = new DslJson<>();

    /**
     * Creates a new DpopProofValidator.
     *
     * @param issuerConfig         the issuer configuration (must have non-null dpopConfig)
     * @param securityEventCounter the security event counter
     * @param replayProtection     shared replay protection instance
     */
    public DpopProofValidator(IssuerConfig issuerConfig,
            SecurityEventCounter securityEventCounter,
            DpopReplayProtection replayProtection) {
        this.config = issuerConfig.getDpopConfig();
        this.securityEventCounter = securityEventCounter;
        this.replayProtection = replayProtection;
        this.algorithmPreferences = issuerConfig.getAlgorithmPreferences();
    }

    /**
     * Validates the DPoP proof for an access token request.
     *
     * @param request        the access token request containing HTTP headers
     * @param accessTokenJwt the decoded access token JWT
     * @param rawAccessToken the raw access token string (for ath computation)
     * @throws TokenValidationException if DPoP validation fails
     */
    @SuppressWarnings({"java:S3776", "java:S1871"}) // Complexity justified for complete DPoP validation flow
    public void validate(AccessTokenRequest request, DecodedJwt accessTokenJwt, String rawAccessToken) {
        // 1. Extract DPoP header (RFC 9449 Section 7: must be single-valued)
        List<String> dpopHeaders = request.httpHeaders().get(DPOP_HEADER_NAME);
        String dpopProofString = null;
        if (dpopHeaders != null && !dpopHeaders.isEmpty()) {
            if (dpopHeaders.size() > 1) {
                rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                        "Multiple DPoP headers found; RFC 9449 requires exactly one");
            }
            dpopProofString = dpopHeaders.getFirst();
            if (dpopProofString != null && dpopProofString.length() > MAX_DPOP_PROOF_SIZE) {
                rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                        "DPoP proof exceeds maximum size of %s bytes".formatted(MAX_DPOP_PROOF_SIZE));
            }
        }

        // Extract cnf.jkt from access token
        Optional<String> cnfJkt = extractCnfJkt(accessTokenJwt);

        if (dpopProofString == null) {
            if (config.isRequired()) {
                // DPoP is required: reject regardless of cnf.jkt
                if (cnfJkt.isPresent()) {
                    rejectWith(EventType.DPOP_PROOF_MISSING, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING,
                            "DPoP proof is required but the DPoP HTTP header is missing");
                } else {
                    rejectWith(EventType.DPOP_CNF_MISSING, JWTValidationLogMessages.WARN.DPOP_CNF_MISSING,
                            "DPoP is required but access token does not contain cnf.jkt claim");
                }
            }
            // Not required: check if access token has cnf.jkt binding
            if (cnfJkt.isPresent()) {
                rejectWith(EventType.DPOP_PROOF_MISSING, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING,
                        "DPoP proof is required but the DPoP HTTP header is missing");
            }
            // No cnf.jkt and not required -> bearer mode, no-op
            return;
        }

        // 2. cnf.jkt must be present if DPoP header is provided
        if (cnfJkt.isEmpty()) {
            rejectWith(EventType.DPOP_CNF_MISSING, JWTValidationLogMessages.WARN.DPOP_CNF_MISSING,
                    "DPoP is required but access token does not contain cnf.jkt claim");
        }
        String expectedThumbprint = cnfJkt.get();

        // 3. Decode DPoP proof JWT manually
        // NonValidatingJwtParser cannot be used because JwtHeader (DSL-JSON @CompiledJson)
        // expects 'jwk' as a String, but DPoP proofs contain 'jwk' as a nested JSON object.
        String[] parts = dpopProofString.split("\\.");
        if (parts.length != 3) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof must have 3 parts (header.payload.signature) but has %s".formatted(parts.length));
        }

        MapRepresentation headerMap;
        MapRepresentation bodyMap;
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
            byte[] bodyBytes = Base64.getUrlDecoder().decode(parts[1]);
            headerMap = MapRepresentation.fromJson(dslJson, headerBytes);
            bodyMap = MapRepresentation.fromJson(dslJson, bodyBytes);
        } catch (IllegalArgumentException | IOException e) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "Failed to decode DPoP proof JWT: %s".formatted(e.getMessage()));
            return; // unreachable but needed for compilation
        }

        // 4. Validate typ header: must be dpop+jwt (case-insensitive)
        String typ = headerMap.getString("typ").orElse(null);
        if (typ == null || !DPOP_TYP.equalsIgnoreCase(typ)) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof typ must be '%s' but was '%s'".formatted(DPOP_TYP, typ));
        }

        // 5. Validate alg header: must be asymmetric
        String alg = headerMap.getString("alg").orElse(null);
        if (alg == null || !algorithmPreferences.isSupported(alg)) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof algorithm '%s' is not supported".formatted(alg));
        }

        // 6. Extract embedded jwk from DPoP proof header
        Optional<Map<String, Object>> jwkOpt = headerMap.getMap("jwk");
        if (jwkOpt.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof header is missing required 'jwk' field");
        }
        Map<String, Object> jwkMap = jwkOpt.get();
        PublicKey proofPublicKey = parsePublicKey(jwkMap);

        // 7. Validate DPoP proof signature
        verifyDpopSignature(parts, proofPublicKey, alg);

        // 8. Validate jti (replay protection)
        Optional<String> jti = bodyMap.getString("jti");
        if (jti.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: jti");
        }
        if (!replayProtection.checkAndStore(jti.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_REPLAY_DETECTED, jti.get());
            securityEventCounter.increment(EventType.DPOP_REPLAY_DETECTED);
            throw new TokenValidationException(EventType.DPOP_REPLAY_DETECTED,
                    "DPoP proof replay detected for jti: %s".formatted(jti.get()));
        }

        // 9. Validate iat (freshness)
        Optional<Number> iat = bodyMap.getNumber("iat");
        if (iat.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: iat");
        }
        long iatSeconds = iat.get().longValue();
        long nowSeconds = System.currentTimeMillis() / 1000;
        long age = nowSeconds - iatSeconds;
        if (age < -60 || age > config.getProofMaxAgeSeconds()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_PROOF_EXPIRED);
            securityEventCounter.increment(EventType.DPOP_PROOF_EXPIRED);
            throw new TokenValidationException(EventType.DPOP_PROOF_EXPIRED,
                    "DPoP proof iat claim is outside acceptable freshness window");
        }

        // 10. Validate ath (access token hash)
        Optional<String> ath = bodyMap.getString("ath");
        if (ath.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: ath");
        }
        String expectedAth = computeAccessTokenHash(rawAccessToken);
        if (!expectedAth.equals(ath.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_ATH_MISMATCH);
            securityEventCounter.increment(EventType.DPOP_ATH_MISMATCH);
            throw new TokenValidationException(EventType.DPOP_ATH_MISMATCH,
                    "DPoP proof ath claim does not match access token hash");
        }

        // 11. Validate JWK Thumbprint
        String computedThumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);
        if (!computedThumbprint.equals(expectedThumbprint)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_THUMBPRINT_MISMATCH, computedThumbprint, expectedThumbprint);
            securityEventCounter.increment(EventType.DPOP_THUMBPRINT_MISMATCH);
            throw new TokenValidationException(EventType.DPOP_THUMBPRINT_MISMATCH,
                    "DPoP proof JWK thumbprint '%s' does not match token cnf.jkt '%s'"
                            .formatted(computedThumbprint, expectedThumbprint));
        }

        LOGGER.debug("DPoP proof validation successful");
    }

    private Optional<String> extractCnfJkt(DecodedJwt accessTokenJwt) {
        return accessTokenJwt.getBody().getNestedMap("cnf")
                .flatMap(cnf -> cnf.getString("jkt"));
    }

    private PublicKey parsePublicKey(Map<String, Object> jwkMap) {
        MapRepresentation jwkRep = new MapRepresentation(jwkMap);
        String kty = jwkRep.getString("kty").orElse(null);
        if (kty == null) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof JWK is missing required 'kty' field or it is not a string");
        }

        try {
            // Create a JwkKey from the map using type-safe accessors
            JwkKey jwkKey = new JwkKey(
                    kty,
                    jwkRep.getString("kid").orElse(null),
                    jwkRep.getString("alg").orElse(null),
                    jwkRep.getString("n").orElse(null),
                    jwkRep.getString("e").orElse(null),
                    jwkRep.getString("crv").orElse(null),
                    jwkRep.getString("x").orElse(null),
                    jwkRep.getString("y").orElse(null)
            );

            return switch (kty) {
                case "RSA" -> JwkKeyHandler.parseRsaKey(jwkKey);
                case "EC" -> JwkKeyHandler.parseEcKey(jwkKey);
                case "OKP" -> JwkKeyHandler.parseOkpKey(jwkKey);
                default -> {
                    rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                            "Unsupported DPoP proof key type: %s".formatted(kty));
                    yield null; // unreachable
                }
            };
        } catch (InvalidKeySpecException e) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "Failed to parse DPoP proof public key: %s".formatted(e.getMessage()));
            return null; // unreachable
        }
    }

    private void verifyDpopSignature(String[] parts, PublicKey publicKey, String algorithm) {
        try {
            SignatureTemplateManager sigManager = new SignatureTemplateManager(algorithmPreferences);
            Signature verifier = sigManager.getSignatureInstance(algorithm);
            verifier.initVerify(publicKey);

            String dataToVerify = parts[0] + "." + parts[1];
            verifier.update(dataToVerify.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

            // Convert ECDSA signatures from IEEE P1363 to ASN.1/DER format if needed
            byte[] verificationSignature = signatureBytes;
            if (algorithm.startsWith("ES")) {
                verificationSignature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(signatureBytes, algorithm);
            }

            if (!verifier.verify(verificationSignature)) {
                rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                        "DPoP proof signature verification failed");
            }
        } catch (InvalidKeyException | SignatureException e) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof signature verification failed: %s".formatted(e.getMessage()));
        }
    }

    private String computeAccessTokenHash(String rawAccessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(rawAccessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private void rejectWith(EventType eventType,
            LogRecord logRecord, String message) {
        LOGGER.warn(logRecord, message);
        securityEventCounter.increment(eventType);
        throw new TokenValidationException(eventType, message);
    }
}
