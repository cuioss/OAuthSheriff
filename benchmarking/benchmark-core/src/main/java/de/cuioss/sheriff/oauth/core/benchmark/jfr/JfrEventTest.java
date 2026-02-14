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
package de.cuioss.sheriff.oauth.core.benchmark.jfr;

import de.cuioss.benchmarking.common.jfr.JfrInstrumentation;
import de.cuioss.tools.logging.CuiLogger;
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.*;

/**
 * Simple test to verify JFR events are working properly.
 */
// cui-rewrite:disable CuiLogRecordPatternRecipe
@SuppressWarnings("java:S2245") // ThreadLocalRandom is appropriate for test scenarios
public class JfrEventTest {

    private static final CuiLogger LOGGER = new CuiLogger(JfrEventTest.class);

    public static void main(String[] args) throws Exception {
        Path outputPath = Path.of("target/benchmark-results/test-jfr.jfr");

        try (Recording recording = new Recording()) {
            recording.enable("de.cuioss.jwt.Operation");
            recording.enable("de.cuioss.jwt.OperationStatistics");
            recording.enable("de.cuioss.jwt.BenchmarkPhase");
            recording.setDestination(outputPath);
            recording.start();

            LOGGER.debug("JFR Recording started...");

            // Create instrumentation
            JfrInstrumentation instrumentation = new JfrInstrumentation();
            try {
                // Record phase event
                instrumentation.recordPhase("TestBenchmark", "warmup", 1, 3, 1, 4);

                // Simulate some operations
                CountDownLatch latch = new CountDownLatch(100);
                @SuppressWarnings("java:S2095") // ExecutorService is properly closed in finally block
                ExecutorService executor = Executors.newFixedThreadPool(4);
                try {
                    for (int i = 0; i < 100; i++) {
                        final int index = i;
                        executor.submit(() -> {
                            try {
                                // Simulate JWT validation with varying latency
                                try (var recorder =
                                             instrumentation.recordOperation("TestBenchmark", "validation")) {
                                    // ThreadLocalRandom is safe for benchmark/test simulation
                                    recorder.withPayloadSize(ThreadLocalRandom.current().nextInt(100, 500))
                                            .withMetadata("issuer", "issuer-" + (index % 3))
                                            .withSuccess(index % 10 != 0); // 90% success rate

                                    // Simulate processing time - ThreadLocalRandom is appropriate for test scenarios
                                    Thread.sleep(ThreadLocalRandom.current().nextInt(1, 10));
                                }
                            } catch (InterruptedException e) {
                                // Restore interrupt status and exit
                                Thread.currentThread().interrupt();
                                LOGGER.error(e, "Test operation interrupted");
                            } catch (IllegalStateException | UnsupportedOperationException e) {
                                LOGGER.error(e, "Error during JFR event test operation");
                            } finally {
                                latch.countDown();
                            }
                        });
                    }

                    // Wait for operations to complete
                    latch.await();
                    Thread.sleep(2000); // Wait for periodic statistics
                } finally {
                    // Shutdown - ensures executor is always closed
                    executor.shutdown();
                    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                        executor.shutdownNow();
                    }
                }
            } finally {
                instrumentation.shutdown();
            }

            recording.stop();
            LOGGER.debug("JFR Recording stopped.");
        }

        // Verify the recording
        LOGGER.debug("\nAnalyzing JFR recording...");
        analyzeRecording(outputPath);
    }

    private static void analyzeRecording(Path jfrFile) throws IOException {
        int operationCount = 0;
        int statisticsCount = 0;
        int phaseCount = 0;

        try (RecordingFile recordingFile = new RecordingFile(jfrFile)) {
            while (recordingFile.hasMoreEvents()) {
                RecordedEvent event = recordingFile.readEvent();
                String eventName = event.getEventType().getName();

                switch (eventName) {
                    case "de.cuioss.jwt.Operation":
                        operationCount++;
                        if (operationCount == 1) {
                            LOGGER.debug("\nFirst Operation Event:");
                            LOGGER.debug("  Operation Type: %s", event.getString("operationType"));
                            LOGGER.debug("  Benchmark: %s", event.getString("benchmarkName"));
                            LOGGER.debug("  Duration: %s ms", event.getDuration().toMillis());
                            LOGGER.debug("  Success: %s", event.getBoolean("success"));
                        }
                        break;
                    case "de.cuioss.jwt.OperationStatistics":
                        statisticsCount++;
                        if (statisticsCount == 1) {
                            LOGGER.debug("\nFirst Statistics Event:");
                            LOGGER.debug("  Sample Count: %s", event.getLong("sampleCount"));
                            LOGGER.debug("  P50 Latency: %s ms", event.getDuration("p50Latency").toMillis());
                            LOGGER.debug("  CV: %s%%", event.getDouble("coefficientOfVariation"));
                        }
                        break;
                    case "de.cuioss.jwt.BenchmarkPhase":
                        phaseCount++;
                        LOGGER.debug("\nPhase Event:");
                        LOGGER.debug("  Phase: %s", event.getString("phase"));
                        LOGGER.debug("  Benchmark: %s", event.getString("benchmarkName"));
                        break;
                    default:
                        // Ignore other event types
                        break;
                }
            }
        }

        LOGGER.debug("\nSummary:");
        LOGGER.debug("  Operation Events: %s", operationCount);
        LOGGER.debug("  Statistics Events: %s", statisticsCount);
        LOGGER.debug("  Phase Events: %s", phaseCount);

        if (operationCount == 0 && statisticsCount == 0) {
            LOGGER.error("\nWARNING: No JWT events found in recording!");
        }
    }
}