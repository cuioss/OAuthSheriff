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
package de.cuioss.benchmarking.common.converter;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.model.BenchmarkData;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Converts JMH benchmark results to the central BenchmarkData model
 */
public class JmhBenchmarkConverter implements BenchmarkConverter {

    private static final Gson GSON = new Gson();
    public static final String THRPT = "thrpt";

    private final BenchmarkType benchmarkType;
    private final String configuredThroughputName;
    private final String configuredLatencyName;

    public JmhBenchmarkConverter(BenchmarkType benchmarkType) {
        this(benchmarkType, null, null);
    }

    public JmhBenchmarkConverter(BenchmarkType benchmarkType,
            String configuredThroughputName, String configuredLatencyName) {
        this.benchmarkType = benchmarkType;
        this.configuredThroughputName = configuredThroughputName;
        this.configuredLatencyName = configuredLatencyName;
    }

    @Override
    public BenchmarkData convert(Path sourcePath) throws IOException {
        String json = Files.readString(sourcePath);
        JsonArray jmhResults = GSON.fromJson(json, JsonArray.class);

        List<BenchmarkData.Benchmark> benchmarks = new ArrayList<>();

        for (JsonElement element : jmhResults) {
            JsonObject jmhBenchmark = element.getAsJsonObject();
            benchmarks.add(convertJmhBenchmark(jmhBenchmark));
        }

        return BenchmarkData.builder()
                .metadata(createMetadata())
                .overview(createOverview(benchmarks))
                .benchmarks(benchmarks)
                .build();
    }

    @Override
    public boolean canConvert(Path sourcePath) {
        return sourcePath.getFileName().toString().endsWith(".json") &&
                (sourcePath.getFileName().toString().contains("jmh") ||
                        sourcePath.getFileName().toString().contains("result"));
    }

    private BenchmarkData.Benchmark convertJmhBenchmark(JsonObject jmh) {
        String name = jmh.get("benchmark").getAsString();
        String mode = jmh.get("mode").getAsString();

        JsonObject primaryMetric = jmh.getAsJsonObject("primaryMetric");
        double score = primaryMetric.get("score").getAsDouble();
        String scoreUnit = primaryMetric.get("scoreUnit").getAsString();

        // Convert units for better readability
        double convertedScore = score;
        String convertedUnit = scoreUnit;

        // Convert ops/ms to ops/s for throughput benchmarks
        if (THRPT.equals(mode) && "ops/ms".equals(scoreUnit)) {
            convertedScore = score * 1000; // Convert ops/ms to ops/s
            convertedUnit = "ops/s";
        }

        Map<String, Double> percentiles = new LinkedHashMap<>();
        if (primaryMetric.has("scorePercentiles")) {
            JsonObject scorePercentiles = primaryMetric.getAsJsonObject("scorePercentiles");
            for (Map.Entry<String, JsonElement> entry : scorePercentiles.entrySet()) {
                double percentileValue = entry.getValue().getAsDouble();
                // Apply same conversion to percentiles
                if (THRPT.equals(mode) && "ops/ms".equals(scoreUnit)) {
                    percentileValue = percentileValue * 1000;
                }
                percentiles.put(entry.getKey(), percentileValue);
            }
        }

        return BenchmarkData.Benchmark.builder()
                .name(extractSimpleName(name))
                .fullName(name)
                .mode(mode)
                .rawScore(convertedScore)
                .score(formatScore(convertedScore, convertedUnit))
                .scoreUnit(convertedUnit)
                .throughput(THRPT.equals(mode) ? formatScore(convertedScore, convertedUnit) : null)
                .latency("avgt".equals(mode) || "sample".equals(mode) ? formatScore(score, scoreUnit) : null)
                .error(primaryMetric.has("scoreError") ? primaryMetric.get("scoreError").getAsDouble() : 0.0)
                .percentiles(percentiles)
                .build();
    }

    private BenchmarkData.Metadata createMetadata() {
        Instant now = Instant.now();
        return BenchmarkData.Metadata.builder()
                .timestamp(now.toString())
                .displayTimestamp(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
                        .withZone(ZoneOffset.UTC)
                        .format(now))
                .benchmarkType(benchmarkType.getDisplayName())
                .reportVersion("2.0")
                .build();
    }

    private BenchmarkData.Overview createOverview(List<BenchmarkData.Benchmark> benchmarks) {
        // Find throughput benchmark: prefer configured name, fall back to max-score heuristic
        Optional<BenchmarkData.Benchmark> bestThroughput = findByConfiguredName(
                benchmarks, configuredThroughputName, THRPT)
                .or(() -> benchmarks.stream()
                        .filter(b -> THRPT.equals(b.getMode()))
                        .max(Comparator.comparing(BenchmarkData.Benchmark::getRawScore)));

        // Find latency benchmark: prefer configured name, fall back to min-score heuristic
        Optional<BenchmarkData.Benchmark> bestLatency = findByConfiguredName(
                benchmarks, configuredLatencyName, "avgt")
                .or(() -> benchmarks.stream()
                        .filter(b -> "avgt".equals(b.getMode()) || "sample".equals(b.getMode()))
                        .min(Comparator.comparing(BenchmarkData.Benchmark::getRawScore)));

        double throughput = bestThroughput.map(BenchmarkData.Benchmark::getRawScore).orElse(0.0);
        // IMPORTANT: Convert latency to milliseconds using the benchmark's unit
        // The rawScore is in the original unit (us/op, ms/op, etc.)
        // We need to convert to milliseconds per operation for consistent reporting
        double latency = bestLatency.map(b -> {
            double rawLatency = b.getRawScore();
            String unit = b.getScoreUnit();
            // Convert from various time units to milliseconds
            return switch (unit) {
                case "us/op" -> rawLatency / 1000.0; // microseconds to milliseconds
                case "ns/op" -> rawLatency / 1_000_000.0; // nanoseconds to milliseconds
                case "s/op" -> rawLatency * 1000.0; // seconds to milliseconds
                default -> rawLatency; // "ms/op" or unknown - assume already in milliseconds
            };
        }).orElse(0.0);

        int score = calculatePerformanceScore(throughput, latency);
        String grade = calculatePerformanceGrade(score);

        return BenchmarkData.Overview.builder()
                .throughput(bestThroughput.map(BenchmarkData.Benchmark::getScore).orElse("N/A"))
                .latency(bestLatency.map(BenchmarkData.Benchmark::getScore).orElse("N/A"))
                .throughputOpsPerSec(throughput)  // Store numeric value used for score calculation
                .latencyMs(latency)               // Store numeric value used for score calculation
                .throughputBenchmarkName(bestThroughput.map(BenchmarkData.Benchmark::getName).orElse(""))
                .latencyBenchmarkName(bestLatency.map(BenchmarkData.Benchmark::getName).orElse(""))
                .performanceScore(score)
                .performanceGrade(grade)
                .performanceGradeClass("grade-" + grade.toLowerCase())
                .build();
    }

    private static Optional<BenchmarkData.Benchmark> findByConfiguredName(
            List<BenchmarkData.Benchmark> benchmarks, String configuredName, String expectedMode) {
        if (configuredName == null || configuredName.isBlank()) {
            return Optional.empty();
        }
        return benchmarks.stream()
                .filter(b -> expectedMode.equals(b.getMode()))
                .filter(b -> b.getName().contains(configuredName) || b.getFullName().contains(configuredName))
                .findFirst();
    }

    private String extractSimpleName(String fullName) {
        int lastDot = fullName.lastIndexOf('.');
        return lastDot >= 0 ? fullName.substring(lastDot + 1) : fullName;
    }

    private String formatScore(double score, String unit) {
        if (score >= 1000) {
            return String.format(Locale.US, "%.1fK %s", score / 1000, unit);
        }
        return String.format(Locale.US, "%.1f %s", score, unit);
    }

    private int calculatePerformanceScore(double throughput, double latency) {
        // Performance scoring per benchmarking/doc/performance-scoring.adoc
        // Performance Score = (Throughput_Score × 0.5) + (Latency_Score × 0.5)
        // Where:
        // - Throughput_Score = Throughput ÷ 100
        // - Latency_Score = 100 ÷ Latency_ms
        // Scores are NOT capped - exceptional performance can exceed 100
        double throughputScore = throughput / 100.0;
        double latencyScore = latency > 0 ? 100.0 / latency : 0.0;
        double rawScore = (throughputScore * 0.5) + (latencyScore * 0.5);
        return (int) Math.round(rawScore);
    }

    private String calculatePerformanceGrade(int score) {
        if (score >= 95) return "A+";
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "F";
    }
}