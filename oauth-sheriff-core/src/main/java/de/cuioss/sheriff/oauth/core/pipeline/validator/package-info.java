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
/**
 * Token validation components for JWT validation pipeline.
 * <p>
 * This package contains specialized validators that verify different aspects
 * of JWT tokens during the validation pipeline:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.TokenStringValidator} - Pre-pipeline string validation</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.TokenSignatureValidator} - Cryptographic signature verification</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.TokenHeaderValidator} - JWT header validation</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.TokenClaimValidator} - Claims validation orchestrator</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.AudienceValidator} - Audience claim validation</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.ExpirationValidator} - Expiration and timing validation</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.MandatoryClaimsValidator} - Required claims validation</li>
 *   <li>{@link de.cuioss.sheriff.oauth.core.pipeline.validator.AuthorizedPartyValidator} - Authorized party validation</li>
 * </ul>
 * <p>
 * These validators are used by the pipeline classes in the parent package
 * ({@link de.cuioss.sheriff.oauth.core.pipeline.AccessTokenValidationPipeline},
 * {@link de.cuioss.sheriff.oauth.core.pipeline.IdTokenValidationPipeline},
 * {@link de.cuioss.sheriff.oauth.core.pipeline.RefreshTokenValidationPipeline})
 * to perform comprehensive token validation.
 *
 * @author Oliver Wolff
 */
package de.cuioss.sheriff.oauth.core.pipeline.validator;
