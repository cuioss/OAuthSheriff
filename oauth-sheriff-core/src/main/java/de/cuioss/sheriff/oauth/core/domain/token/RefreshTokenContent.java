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
package de.cuioss.sheriff.oauth.core.domain.token;

import de.cuioss.sheriff.oauth.core.TokenType;
import de.cuioss.sheriff.oauth.core.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.util.Map;

/**
 * Represents the content of an OAuth 2.0 Refresh Token in JWT format.
 * <p>
 * While most OAuth 2.0 implementations use opaque tokens for refresh tokens,
 * some authorization servers issue JWT-formatted refresh tokens. This class
 * provides a container for such JWT-based refresh tokens.
 * <p>
 * Unlike {@link AccessTokenContent} and {@link IdTokenContent} which extend {@link BaseTokenContent},
 * this class implements {@link MinimalTokenContent} directly because:
 * <ul>
 *   <li>Refresh tokens often have minimal to no claims</li>
 *   <li>The structure can vary significantly between authorization servers</li>
 *   <li>Validation requirements are minimal for refresh tokens</li>
 * </ul>
 * <p>
 * This class maintains the raw token string and any claims that might be present in the
 * JWT structure.
 * However, it does not enforce specific validation rules as refresh tokens
 * are meant to be used only with the token endpoint, not validated by client applications.
 * <p>
 * This implementation follows guidance from:
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JWT</a></li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@ToString
@EqualsAndHashCode
public class RefreshTokenContent implements MinimalTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private final String rawToken;

    /**
     * For cases the idp returns a JWT as Refresh-Token, this method returns a non-validated-claims-representation
     * of the validation.
     * <em>Note:</em> This is validation is not validated in any way
     * It is never null but be empty
     */
    @Getter
    private final Map<String, ClaimValue> claims;

    public RefreshTokenContent(String rawToken, Map<String, ClaimValue> claims) {
        this.rawToken = rawToken;
        this.claims = claims;
    }

    /**
     * Gets the validation type.
     *
     * @return always TokenType.REFRESH_TOKEN
     */
    @Override
    public TokenType getTokenType() {
        return TokenType.REFRESH_TOKEN;
    }

}