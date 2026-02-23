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
package de.cuioss.sheriff.oauth.core.jwks.key;

import de.cuioss.sheriff.oauth.core.json.JwkKey;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for handling JWK (JSON Web Key) operations.
 * <p>
 * This class provides methods for parsing and validating RSA and EC keys from JWK format.
 * It isolates the low-level cryptographic operations from the JWKSKeyLoader class.
 * <p>
 * This class uses standard JDK cryptographic providers for key parsing and validation.
 * It supports all standard elliptic curves (P-256, P-384, P-521) and RSA keys
 * as defined in RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms).
 * <p>
 * All operations use the standard JDK cryptographic providers available in Java 11+,
 * ensuring excellent compatibility with GraalVM native image compilation.
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/OAuthSheriff/tree/main/doc/specification/security.adoc">Security Specification</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwkKeyHandler {

    private static final String MESSAGE = "Invalid Base64 URL encoded value for '%s'";
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";

    // Cache for KeyFactory instances to improve performance
    private static final Map<String, KeyFactory> KEY_FACTORY_CACHE = new ConcurrentHashMap<>();


    /**
     * Parses an RSA public key from a JwkKey record.
     *
     * @param jwk the JwkKey record containing RSA parameters
     * @return the parsed RSA public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseRsaKey(JwkKey jwk) throws InvalidKeySpecException {
        // Use JwkKey's transformation methods with proper validation
        BigInteger exponent = jwk.getExponentAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("e")));
        BigInteger modulus = jwk.getModulusAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("n")));

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = getKeyFactory(RSA_KEY_TYPE);
        return factory.generatePublic(spec);
    }


    /**
     * Parse an EC key from a JwkKey record.
     *
     * @param jwk the JwkKey record containing EC parameters
     * @return the EC public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseEcKey(JwkKey jwk) throws InvalidKeySpecException {
        // Use JwkKey's transformation methods with proper validation
        String curve = jwk.getCrv()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("crv")));
        BigInteger x = jwk.getXCoordinateAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("x")));
        BigInteger y = jwk.getYCoordinateAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("y")));

        // Create EC point
        ECPoint point = new ECPoint(x, y);

        // Get EC parameter spec for the curve
        ECParameterSpec params = getEcParameterSpec(curve);

        // Create EC public key
        ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
        KeyFactory factory = getKeyFactory(EC_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Get the EC parameter spec for a given curve using standard JDK providers.
     *
     * @param curve the curve name (e.g., "P-256", "P-384", "P-521")
     * @return the EC parameter spec
     * @throws InvalidKeySpecException if the curve is not supported
     */
    private static ECParameterSpec getEcParameterSpec(String curve) throws InvalidKeySpecException {
        // Map JWK curve name to standard JDK curve name
        String jdkCurveName = switch (curve) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> null;
        };

        if (jdkCurveName == null) {
            throw new InvalidKeySpecException("EC curve " + curve + " is not supported");
        }

        try {
            // Use standard JDK AlgorithmParameters to get the curve parameters
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(jdkCurveName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new InvalidKeySpecException("Failed to get EC parameters for curve: " + curve, e);
        }
    }

    /**
     * Get a KeyFactory instance for the specified algorithm.
     * Uses a cache to avoid creating new instances repeatedly.
     *
     * @param algorithm the algorithm name
     * @return the KeyFactory instance
     * @throws IllegalStateException if the algorithm is not available
     */
    private static KeyFactory getKeyFactory(String algorithm) {
        return KEY_FACTORY_CACHE.computeIfAbsent(algorithm, alg -> {
            try {
                return KeyFactory.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Failed to create KeyFactory for " + alg, e);
            }
        });
    }

    /**
     * Determine the EC algorithm based on the curve.
     *
     * @param curve the curve name
     * @return the algorithm name, defaults to "ES256" for unknown curves
     */
    public static String determineEcAlgorithm(String curve) {
        return switch (curve) {
            case "P-256" -> "ES256";
            case "P-384" -> "ES384";
            case "P-521" -> "ES512";
            default -> "ES256"; // Default to ES256
        };
    }
}
