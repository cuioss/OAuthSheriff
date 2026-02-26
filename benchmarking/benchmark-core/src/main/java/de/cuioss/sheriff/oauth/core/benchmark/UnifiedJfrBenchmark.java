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
package de.cuioss.sheriff.oauth.core.benchmark;

import de.cuioss.benchmarking.common.jfr.JfrInstrumentation;
import de.cuioss.sheriff.oauth.core.TokenValidator;
import de.cuioss.sheriff.oauth.core.benchmark.delegates.CoreValidationDelegate;
import de.cuioss.sheriff.oauth.core.benchmark.delegates.ErrorLoadDelegate;
import de.cuioss.sheriff.oauth.core.domain.token.AccessTokenContent;
import de.cuioss.sheriff.oauth.core.metrics.TokenValidatorMonitorConfig;
import de.cuioss.tools.logging.CuiLogger;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Unified JFR-instrumented benchmark that includes all benchmark scenarios.
 * This class uses delegates to avoid code duplication and provides comprehensive
 * JFR instrumentation for all benchmark types.
 *
 * @author Oliver Wolff
 */
@State(Scope.Benchmark)
@SuppressWarnings("java:S112")
public class UnifiedJfrBenchmark {

    private static final CuiLogger LOGGER = new CuiLogger(UnifiedJfrBenchmark.class);

    // Operation type constants
    private static final String ERROR_VALIDATION_OPERATION = "error-validation";
    private static final String MIXED_VALIDATION_OPERATION = "mixed-validation";
    private static final String VALIDATION_OPERATION = "validation";

    // Token type constants
    private static final String TOKEN_TYPE_FULL_SPECTRUM = "full_spectrum";


    // Issuer constants
    private static final String BENCHMARK_ISSUER = "benchmark-issuer";
    private static final String UNKNOWN_ISSUER = "unknown";

    // Error type constants
    private static final String ERROR_EXPIRED = "expired";
    private static final String ERROR_MALFORMED = "malformed";
    private static final String ERROR_INVALID_SIGNATURE = "invalid_signature";
    private static final String ERROR_TYPE_VALID = "valid";

    // Configuration constants
    private static final int APPROXIMATE_TOKEN_SIZE = 200;
    public static final String ISSUER = "issuer";

    private MockTokenRepository tokenRepository;
    private TokenValidator tokenValidator;
    private CoreValidationDelegate coreValidationDelegate;
    private ErrorLoadDelegate errorLoadDelegate0;
    private ErrorLoadDelegate errorLoadDelegate50;
    private JfrInstrumentation jfrInstrumentation;

    @Setup(Level.Trial)
    public void setup() {
        // Initialize JFR instrumentation
        jfrInstrumentation = new JfrInstrumentation();

        // Initialize token repository with cache size configured for 10% of tokens
        MockTokenRepository.Config config = MockTokenRepository.Config.builder()
                .cacheSize(60) // 10% of default 600 tokens
                .build();
        tokenRepository = new MockTokenRepository(config);

        // Create token validator with cache configuration
        tokenValidator = tokenRepository.createTokenValidator(
                TokenValidatorMonitorConfig.builder()
                        .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                        .windowSize(10000)
                        .build(),
                config);

        // Initialize delegates
        coreValidationDelegate = new CoreValidationDelegate(tokenValidator, tokenRepository);
        errorLoadDelegate0 = new ErrorLoadDelegate(tokenValidator, tokenRepository, 0);
        errorLoadDelegate50 = new ErrorLoadDelegate(tokenValidator, tokenRepository, 50);
    }

    @Setup(Level.Iteration)
    public void setupIteration() {
        // Record benchmark phase event at iteration start
        String benchmarkName = this.getClass().getSimpleName();
        String phase = "measurement";
        int threads = Thread.activeCount();

        jfrInstrumentation.recordPhase(benchmarkName, phase, 0, 0, 1, threads);
    }


    @TearDown(Level.Trial)
    public void tearDown() {
        // Export metrics
        if (tokenValidator != null) {
            try {
                LibraryMetricsExporter.exportMetrics(tokenValidator.getPerformanceMonitor());
            } catch (IOException e) {
                LOGGER.debug("Failed to export metrics during teardown", e);
            }
        }

        // Shutdown JFR instrumentation
        if (jfrInstrumentation != null) {
            jfrInstrumentation.shutdown();
        }
    }

    /**
     * Measures average validation time for single-threaded token validation with JFR instrumentation using full token spectrum.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public AccessTokenContent measureAverageTimeWithJfr() {
        String token = coreValidationDelegate.getCurrentToken(TOKEN_TYPE_FULL_SPECTRUM);

        try (var recorder = jfrInstrumentation.recordOperation("measureAverageTimeWithJfr", VALIDATION_OPERATION)) {
            recorder.withPayloadSize(token.length())
                    .withMetadata(ISSUER, tokenRepository.getTokenIssuer(token).orElse(null));

            AccessTokenContent result = coreValidationDelegate.validateWithFullSpectrum();
            recorder.withSuccess(true);
            return result;
        }
    }

    /**
     * Measures token validation throughput under concurrent load with JFR instrumentation using full token spectrum.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public AccessTokenContent measureThroughputWithJfr() {
        String token = coreValidationDelegate.getCurrentToken(TOKEN_TYPE_FULL_SPECTRUM);

        try (var recorder = jfrInstrumentation.recordOperation("measureThroughputWithJfr", VALIDATION_OPERATION)) {
            recorder.withPayloadSize(token.length())
                    .withMetadata(ISSUER, tokenRepository.getTokenIssuer(token).orElse(null));

            AccessTokenContent result = coreValidationDelegate.validateWithFullSpectrum();
            recorder.withSuccess(true);
            return result;
        }
    }

    // ========== Error Load Benchmarks ==========

    /**
     * Measures validation performance for valid tokens with JFR instrumentation using full token spectrum.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public AccessTokenContent validateValidTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateValidTokenWithJfr", VALIDATION_OPERATION)) {
            String token = coreValidationDelegate.getCurrentToken(TOKEN_TYPE_FULL_SPECTRUM);
            recorder.withPayloadSize(token.length())
                    .withMetadata(ISSUER, tokenRepository.getTokenIssuer(token).orElse(null));

            AccessTokenContent result = coreValidationDelegate.validateWithFullSpectrum();
            recorder.withSuccess(true);
            return result;
        }
    }

    /**
     * Measures validation performance for expired tokens with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateExpiredTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateExpiredTokenWithJfr", ERROR_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(APPROXIMATE_TOKEN_SIZE)
                    .withMetadata(ISSUER, BENCHMARK_ISSUER)
                    .withError(ERROR_EXPIRED);

            Object result = errorLoadDelegate0.validateExpired();
            recorder.withSuccess(false);
            return result;
        }
    }

    /**
     * Measures validation performance for malformed tokens with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateMalformedTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateMalformedTokenWithJfr", ERROR_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(25) // Length of malformed token
                    .withMetadata(ISSUER, UNKNOWN_ISSUER)
                    .withError(ERROR_MALFORMED);

            Object result = errorLoadDelegate0.validateMalformed();
            recorder.withSuccess(false);
            return result;
        }
    }

    /**
     * Measures validation performance for tokens with invalid signatures with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateInvalidSignatureTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateInvalidSignatureTokenWithJfr", ERROR_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(APPROXIMATE_TOKEN_SIZE)
                    .withMetadata(ISSUER, BENCHMARK_ISSUER)
                    .withError(ERROR_INVALID_SIGNATURE);

            Object result = errorLoadDelegate0.validateInvalidSignature();
            recorder.withSuccess(false);
            return result;
        }
    }

    /**
     * Measures validation performance with mixed valid/invalid tokens (0% error rate) with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateMixedTokens0WithJfr(Blackhole blackhole) {
        return validateMixedTokensWithJfr(blackhole, errorLoadDelegate0, "validateMixedTokens0WithJfr");
    }

    /**
     * Measures validation performance with mixed valid/invalid tokens (50% error rate) with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateMixedTokens50WithJfr(Blackhole blackhole) {
        return validateMixedTokensWithJfr(blackhole, errorLoadDelegate50, "validateMixedTokens50WithJfr");
    }

    private Object validateMixedTokensWithJfr(Blackhole blackhole, ErrorLoadDelegate delegate, String operationName) {
        String token = delegate.selectToken();
        String errorType = delegate.getErrorType(token);
        boolean isValid = ERROR_TYPE_VALID.equals(errorType);

        try (var recorder = jfrInstrumentation.recordOperation(operationName, MIXED_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(token.length())
                    .withMetadata(ISSUER, isValid ? tokenRepository.getTokenIssuer(token).orElse(null) : BENCHMARK_ISSUER);

            if (!isValid) {
                recorder.withError(errorType);
            }

            Object result = delegate.validateMixed(blackhole);
            recorder.withSuccess(isValid);
            return result;
        }
    }

}