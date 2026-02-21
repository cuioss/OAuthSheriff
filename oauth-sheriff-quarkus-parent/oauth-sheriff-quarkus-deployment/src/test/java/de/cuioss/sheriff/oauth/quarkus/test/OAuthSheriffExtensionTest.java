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
package de.cuioss.sheriff.oauth.quarkus.test;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.QuarkusUnitTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Test to verify the OAuth Sheriff extension is properly registered and configured.
 * 
 * Uses QuarkusUnitTest to properly test the extension in a Quarkus context.
 */
@EnableTestLogger
@DisplayName("OAuth Sheriff Extension Registration Test")
class CuiJwtExtensionTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withEmptyApplication()
            .setLogRecordPredicate(log -> true);

    @Test
    @DisplayName("Should register the extension")
    void shouldRegisterExtension() {
    }
}
