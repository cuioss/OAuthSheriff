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
package de.cuioss.benchmarking.common.base;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AbstractBenchmarkBase}.
 *
 * @author Oliver Wolff
 */
class AbstractBenchmarkBaseTest {

    @TempDir
    Path tempDir;

    private TestBenchmarkImplementation testBenchmark;

    @BeforeEach
    void setUp() {
        testBenchmark = new TestBenchmarkImplementation();
    }

    @Test
    void shouldInitializeFieldsOnSetup() {
        // Before setup
        assertNull(testBenchmark.serviceUrl);
        assertNull(testBenchmark.benchmarkResultsDir);
        assertNull(testBenchmark.httpClient);

        // After setup
        testBenchmark.setupBase();

        assertNotNull(testBenchmark.benchmarkResultsDir);
        assertNotNull(testBenchmark.httpClient);
        assertTrue(testBenchmark.additionalSetupCalled);
    }

    @Test
    void shouldUseBenchmarkResultsDirFromSystemProperty() {
        String customDir = tempDir.toString() + "/custom-results";
        System.setProperty("benchmark.results.dir", customDir);

        testBenchmark.setupBase();
        assertEquals(customDir, testBenchmark.benchmarkResultsDir);

        System.clearProperty("benchmark.results.dir");
    }

    @Test
    void shouldUseDefaultBenchmarkResultsDir() {
        testBenchmark.setupBase();
        assertEquals("target/benchmark-results", testBenchmark.benchmarkResultsDir);
    }

    @Test
    void shouldCreateBaseRequestWithFullUrl() {
        testBenchmark.setupBase();
        HttpRequest.Builder builder = testBenchmark.createBaseRequest("https://example.com/api/test");

        HttpRequest request = builder.build();
        assertEquals("https://example.com/api/test", request.uri().toString());
        assertTrue(request.headers().firstValue("Content-Type").isPresent());
        assertEquals("application/json", request.headers().firstValue("Content-Type").get());
        assertTrue(request.headers().firstValue("Accept").isPresent());
        assertEquals("application/json", request.headers().firstValue("Accept").get());
    }

    @Test
    void shouldCreateBaseRequestWithBaseUrlAndPath() {
        testBenchmark.setupBase();
        HttpRequest.Builder builder = testBenchmark.createBaseRequest("https://example.com", "/api/test");

        HttpRequest request = builder.build();
        assertEquals("https://example.com/api/test", request.uri().toString());
    }

    @Test
    void shouldValidateResponseSuccessfully() {
        HttpResponse<String> mockResponse = createMockResponse(200, "OK");

        // Should not throw exception
        assertDoesNotThrow(() -> testBenchmark.validateResponse(mockResponse, 200));
    }

    @Test
    void shouldThrowExceptionForUnexpectedStatus() {
        HttpResponse<String> mockResponse = createMockResponse(404, "Not Found");

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> testBenchmark.validateResponse(mockResponse, 200)
        );

        assertTrue(exception.getMessage().contains("Expected status 200 but got 404"));
        assertTrue(exception.getMessage().contains("Not Found"));
    }

    @Test
    void shouldCallTeardownMethods() {
        testBenchmark.tearDown();

        assertTrue(testBenchmark.additionalTeardownCalled);
    }

    @Test
    void shouldThrowExceptionWhenSendingRequestWithoutSetup() {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://example.com"))
                .build();

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> testBenchmark.sendRequest(request)
        );

        assertTrue(exception.getMessage().contains("HTTP client not initialized"));
    }

    /**
     * Test implementation of AbstractBenchmarkBase for testing purposes.
     */
    private static class TestBenchmarkImplementation extends AbstractBenchmarkBase {

        boolean additionalSetupCalled = false;
        boolean additionalTeardownCalled = false;
        boolean exportMetricsCalled = false;

        @Override
        protected void performAdditionalSetup() {
            additionalSetupCalled = true;
        }

        @Override
        protected void performAdditionalTeardown() {
            additionalTeardownCalled = true;
        }

        @Override
        public void exportBenchmarkMetrics() {
            exportMetricsCalled = true;
        }
    }

    /**
     * Creates a mock HTTP response for testing.
     */
    private HttpResponse<String> createMockResponse(int statusCode, String body) {
        return new HttpResponse<>() {
            @Override
            public int statusCode() {
                return statusCode;
            }

            @Override
            public HttpRequest request() {
                return null;
            }

            @Override
            public Optional<HttpResponse<String>> previousResponse() {
                return Optional.empty();
            }

            @Override
            public HttpHeaders headers() {
                return HttpHeaders.of(Map.of(), (s1, s2) -> true);
            }

            @Override
            public String body() {
                return body;
            }

            @Override
            public Optional<SSLSession> sslSession() {
                return Optional.empty();
            }

            @Override
            public URI uri() {
                return URI.create("https://example.com");
            }

            @Override
            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_1_1;
            }
        };
    }
}