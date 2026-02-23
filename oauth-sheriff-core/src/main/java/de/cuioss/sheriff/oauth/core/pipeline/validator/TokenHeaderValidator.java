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
package de.cuioss.sheriff.oauth.core.pipeline.validator;

import de.cuioss.sheriff.oauth.core.IssuerConfig;
import de.cuioss.sheriff.oauth.core.JWTValidationLogMessages;
import de.cuioss.sheriff.oauth.core.exception.TokenValidationException;
import de.cuioss.sheriff.oauth.core.json.JwtHeader;
import de.cuioss.sheriff.oauth.core.pipeline.DecodedJwt;
import de.cuioss.sheriff.oauth.core.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;

/**
 * Validator for JWT Token headers.
 * <p>
 * This class validates the following header elements:
 * <ul>
 *   <li>Algorithm (alg) - against configured SignatureAlgorithmPreferences</li>
 *   <li>Issuer (iss) - against configured expected issuer</li>
 *   <li>Absence of embedded JWK - to prevent CVE-2018-0114 attacks</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 * <p>
 * For more details on the validation process, see the
 * <a href="https://github.com/cuioss/OAuthSheriff/tree/main/doc/specification/technical-components.adoc#token-validation-pipeline">Token Validation Pipeline</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@Builder
public class TokenHeaderValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenHeaderValidator.class);

    private final IssuerConfig issuerConfig;
    /**
     * The counter for security events.
     */
   
    private final SecurityEventCounter securityEventCounter;

    /**
     * Constructs a TokenHeaderValidator with the specified IssuerConfig.
     *
     * @param issuerConfig         the issuer configuration
     * @param securityEventCounter the counter for security events
     */
    public TokenHeaderValidator(IssuerConfig issuerConfig, SecurityEventCounter securityEventCounter) {
        this.issuerConfig = issuerConfig;
        this.securityEventCounter = securityEventCounter;
    }


    /**
     * Validates a decoded JWT Token's header.
     * <p>
     * This validator checks:
     * <ul>
     *   <li>Algorithm (alg) claim presence and support</li>
     *   <li>Key ID (kid) claim presence for signature validation</li>
     *   <li>Absence of embedded JWK to prevent CVE-2018-0114 attacks</li>
     * </ul>
     * <p>
     * Note: Issuer validation is now performed at the TokenValidator level during
     * issuer configuration resolution, not here.
     * </p>
     *
     * @param decodedJwt the decoded JWT Token to validate
     * @throws TokenValidationException if the token header is invalid
     */
    public void validate(DecodedJwt decodedJwt) {
        LOGGER.trace("Validating token header");

        validateAlgorithm(decodedJwt);
        validateKeyId(decodedJwt);
        // Issuer validation removed - now handled in TokenValidator.resolveIssuerConfig()
        validateNoEmbeddedJwk(decodedJwt);

        LOGGER.debug("Token header is valid");
    }

    /**
     * Validates that the token does not contain an embedded JWK in the header.
     * This is protection against the embedded JWK attack (CVE-2018-0114).
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the token contains an embedded JWK
     */
    @SuppressWarnings("java:S3655") // owolff: False Positive: isPresent is checked before calling get()
    private void validateNoEmbeddedJwk(DecodedJwt decodedJwt) {
        JwtHeader header = decodedJwt.getHeader();
        if (header.getJwk().isPresent()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM, "Embedded JWK");
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM,
                    "Embedded JWK in token header is not allowed"
            );
        }
    }

    /**
     * Validates the validation's algorithm against the configured algorithm preferences.
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the algorithm is invalid
     */
    private void validateAlgorithm(DecodedJwt decodedJwt) {
        var algorithm = decodedJwt.getAlg();

        if (algorithm.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, "alg");
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.MISSING_CLAIM,
                    "Missing required algorithm (alg) claim in token header"
            );
        }

        if (!issuerConfig.getAlgorithmPreferences().isSupported(algorithm.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM, algorithm.get());
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM,
                    "Unsupported algorithm: %s".formatted(algorithm.get())
            );
        }

        LOGGER.debug("Algorithm is valid: %s", algorithm.get());
    }

    /**
     * Validates that the token contains a key ID (kid) claim in the header.
     * The kid is required for signature validation to identify the correct key.
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the kid claim is missing
     */
    private void validateKeyId(DecodedJwt decodedJwt) {
        var kid = decodedJwt.getKid();
        if (kid.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, "kid");
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            JwtHeader header = decodedJwt.getHeader();
            StringBuilder headerInfo = new StringBuilder("Available header claims:");
            boolean hasAny = false;

            if (header.getAlg().isPresent()) {
                headerInfo.append(" alg=").append(header.alg());
                hasAny = true;
            }

            var kidOpt = header.getKid();
            if (kidOpt.isPresent()) {
                headerInfo.append(hasAny ? "," : "").append(" kid=").append(kidOpt.orElse(""));
                hasAny = true;
            }

            var typOpt = header.getTyp();
            if (typOpt.isPresent()) {
                headerInfo.append(hasAny ? "," : "").append(" typ=").append(typOpt.orElse(""));
                hasAny = true;
            }

            if (!hasAny) {
                headerInfo.append(" none");
            }

            throw new TokenValidationException(
                    SecurityEventCounter.EventType.MISSING_CLAIM,
                    "Missing required key ID (kid) claim in token header. " + headerInfo
            );
        }
        LOGGER.debug("Key ID is valid: %s", kid.get());
    }

}