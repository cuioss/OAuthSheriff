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
package de.cuioss.sheriff.oauth.core.json;

import com.dslplatform.json.CompiledJson;

import java.util.Optional;

/**
 * JWT Header representation for DSL-JSON deserialization.
 * <p>
 * This record represents the JWT header structure as defined in RFC 7515 (JWS)
 * and RFC 7519 (JWT), providing type-safe access to header parameters.
 * <p>
 * The header contains cryptographic metadata needed for JWT validation:
 * <ul>
 *   <li>Algorithm specification for signature verification</li>
 *   <li>Key identification for key lookup</li>
 *   <li>Content type information</li>
 *   <li>Key discovery metadata</li>
 * </ul>
 * <p>
 * This implementation follows the specification requirements:
 * <ul>
 *   <li>Uses Optional for all optional parameters per RFC specifications</li>
 *   <li>Provides null-safe access to header values</li>
 *   <li>Enables compile-time JSON processing with DSL-JSON</li>
 * </ul>
 * <p>
 * For more details on JWT header structure, see:
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4">RFC 7515 - 4. JWS Header</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519#section-5">RFC 7519 - 5. JWT Header</a></li>
 * </ul>
 *
 * @param alg The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to secure the JWS.
 *            REQUIRED by RFC 7515 for all JWS/JWT tokens.
 * @param typ The "typ" (type) Header Parameter is used to declare the media type of the complete JWS.
 *            OPTIONAL by RFC 7515. When present, it is RECOMMENDED to use "JWT".
 * @param kid The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the JWS.
 *            OPTIONAL by RFC 7515. Used for key lookup in multi-key scenarios.
 * @param jku The "jku" (JWK Set URL) Header Parameter is a URI that refers to a resource for a set of JSON-encoded public keys.
 *            OPTIONAL by RFC 7515. Used for key discovery.
 * @param jwk The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds to the key used to digitally sign the JWS.
 *            OPTIONAL by RFC 7515. Contains the actual key material as a JWK. Stored as String for DSL-JSON compatibility.
 * @param x5u The "x5u" (X.509 URL) Header Parameter is a URI that refers to a resource for the X.509 public key certificate.
 *            OPTIONAL by RFC 7515. Used for X.509-based key discovery.
 * @param x5c The "x5c" (X.509 Certificate Chain) Header Parameter contains the X.509 public key certificate.
 *            OPTIONAL by RFC 7515. Contains the actual certificate chain. Stored as String for DSL-JSON compatibility.
 * @param x5t The "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter is a base64url encoded SHA-1 thumbprint.
 *            OPTIONAL by RFC 7515. Used for certificate identification.
 * @param x5tS256 The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter is a base64url encoded SHA-256 thumbprint.
 *               OPTIONAL by RFC 7515. Preferred over x5t due to SHA-256 being more secure than SHA-1.
 * @param cty The "cty" (content type) Header Parameter is used to declare the media type of the secured content (the payload).
 *            OPTIONAL by RFC 7515. Only needed when the payload is another JWT/JWS.
 * @param crit The "crit" (critical) Header Parameter indicates the extensions that MUST be understood and processed.
 *             OPTIONAL by RFC 7515. Contains a list of header parameter names that are critical. Stored as String for DSL-JSON compatibility.
 *
 * @author Oliver Wolff
 */
@CompiledJson
public record JwtHeader(
String alg,
String typ,
String kid,
String jku,
String jwk,
String x5u,
String x5c,
String x5t,
String x5tS256,
String cty,
String crit
) {

    /**
     * Gets the algorithm parameter as Optional.
     * 
     * @return Optional containing the algorithm, empty if null or empty
     */
    public Optional<String> getAlg() {
        return Optional.ofNullable(alg).filter(s -> !s.trim().isEmpty());
    }

    /**
     * Gets the type parameter as Optional.
     * 
     * @return Optional containing the type, empty if null
     */
    public Optional<String> getTyp() {
        return Optional.ofNullable(typ);
    }

    /**
     * Gets the key ID parameter as Optional.
     * 
     * @return Optional containing the key ID, empty if null
     */
    public Optional<String> getKid() {
        return Optional.ofNullable(kid);
    }

    /**
     * Gets the JWK Set URL parameter as Optional.
     * 
     * @return Optional containing the JWK Set URL, empty if null
     */
    public Optional<String> getJku() {
        return Optional.ofNullable(jku);
    }

    /**
     * Gets the JSON Web Key parameter as Optional.
     * 
     * @return Optional containing the JWK, empty if null
     */
    public Optional<String> getJwk() {
        return Optional.ofNullable(jwk);
    }

    /**
     * Gets the X.509 URL parameter as Optional.
     * 
     * @return Optional containing the X.509 URL, empty if null
     */
    public Optional<String> getX5u() {
        return Optional.ofNullable(x5u);
    }

    /**
     * Gets the X.509 Certificate Chain parameter as Optional.
     * 
     * @return Optional containing the X.509 certificate chain, empty if null
     */
    public Optional<String> getX5c() {
        return Optional.ofNullable(x5c);
    }

    /**
     * Gets the X.509 Certificate SHA-1 Thumbprint parameter as Optional.
     * 
     * @return Optional containing the thumbprint, empty if null
     */
    public Optional<String> getX5t() {
        return Optional.ofNullable(x5t);
    }

    /**
     * Gets the X.509 Certificate SHA-256 Thumbprint parameter as Optional.
     * 
     * @return Optional containing the SHA-256 thumbprint, empty if null
     */
    public Optional<String> getX5tS256() {
        return Optional.ofNullable(x5tS256);
    }

    /**
     * Gets the content type parameter as Optional.
     * 
     * @return Optional containing the content type, empty if null
     */
    public Optional<String> getCty() {
        return Optional.ofNullable(cty);
    }

    /**
     * Gets the critical parameter as Optional.
     * 
     * @return Optional containing the critical parameter, empty if null
     */
    public Optional<String> getCrit() {
        return Optional.ofNullable(crit);
    }
}