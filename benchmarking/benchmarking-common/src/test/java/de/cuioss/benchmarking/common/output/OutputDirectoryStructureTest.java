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
package de.cuioss.benchmarking.common.output;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OutputDirectoryStructure}.
 */
class OutputDirectoryStructureTest {

    @Test
    void constructorShouldSetAllPaths(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        assertEquals(benchmarkResultsDir, structure.getBenchmarkResultsDir());
        assertEquals(benchmarkResultsDir.resolve("gh-pages-ready"), structure.getDeploymentDir());
        assertEquals(benchmarkResultsDir.resolve("gh-pages-ready"), structure.getHtmlDir());
        assertEquals(benchmarkResultsDir.resolve("gh-pages-ready/data"), structure.getDataDir());
        assertEquals(benchmarkResultsDir.resolve("gh-pages-ready/badges"), structure.getBadgesDir());
        assertEquals(benchmarkResultsDir.resolve("gh-pages-ready/api"), structure.getApiDir());
        assertEquals(benchmarkResultsDir.resolve("history"), structure.getHistoryDir());
        assertEquals(benchmarkResultsDir.resolve("prometheus"), structure.getPrometheusRawDir());
        assertEquals(benchmarkResultsDir.resolve("wrk"), structure.getWrkDir());
    }

    @Test
    void constructorShouldRejectNullParameter() {
        assertThrows(NullPointerException.class, () -> new OutputDirectoryStructure(null));
    }

    @Test
    void ensureDirectoriesShouldCreateDeploymentDirectories(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Initially, deployment directories should not exist
        assertFalse(Files.exists(structure.getDeploymentDir()));
        assertFalse(Files.exists(structure.getDataDir()));
        assertFalse(Files.exists(structure.getBadgesDir()));
        assertFalse(Files.exists(structure.getApiDir()));

        // Ensure deployment directories
        structure.ensureDirectories();

        // Deployment directories should now exist
        assertTrue(Files.exists(structure.getDeploymentDir()));
        assertTrue(Files.isDirectory(structure.getDeploymentDir()));
        assertTrue(Files.exists(structure.getDataDir()));
        assertTrue(Files.isDirectory(structure.getDataDir()));
        assertTrue(Files.exists(structure.getBadgesDir()));
        assertTrue(Files.isDirectory(structure.getBadgesDir()));
        assertTrue(Files.exists(structure.getApiDir()));
        assertTrue(Files.isDirectory(structure.getApiDir()));
    }

    @Test
    void ensureDirectoriesShouldNotCreateNonDeploymentDirectories(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Non-deployed directories should not exist yet (created on-demand)
        Path historyPath = benchmarkResultsDir.resolve("history");
        Path prometheusPath = benchmarkResultsDir.resolve("prometheus");
        Path wrkPath = benchmarkResultsDir.resolve("wrk");
        assertFalse(Files.exists(historyPath));
        assertFalse(Files.exists(prometheusPath));
        assertFalse(Files.exists(wrkPath));

        // Ensure deployment directories only
        structure.ensureDirectories();

        // Non-deployed directories should still not exist (only created when accessed)
        assertFalse(Files.exists(historyPath));
        assertFalse(Files.exists(prometheusPath));
        assertFalse(Files.exists(wrkPath));

        // Now access the directories to trigger creation
        assertTrue(Files.exists(structure.getHistoryDir()));
        assertTrue(Files.isDirectory(structure.getHistoryDir()));
        assertTrue(Files.exists(structure.getPrometheusRawDir()));
        assertTrue(Files.isDirectory(structure.getPrometheusRawDir()));
        assertTrue(Files.exists(structure.getWrkDir()));
        assertTrue(Files.isDirectory(structure.getWrkDir()));

        // Verify they were created in the correct locations
        assertTrue(Files.exists(historyPath));
        assertTrue(Files.exists(prometheusPath));
        assertTrue(Files.exists(wrkPath));
    }

    @Test
    void ensureDirectoriesShouldBeIdempotent(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Create directories first time
        structure.ensureDirectories();

        // Create some test files to ensure they're preserved
        Path testFile1 = structure.getDataDir().resolve("test1.json");
        Path testFile2 = structure.getBadgesDir().resolve("test2.json");
        Files.writeString(testFile1, "test content 1");
        Files.writeString(testFile2, "test content 2");

        // Call ensureDirectories again - should not fail
        assertDoesNotThrow(structure::ensureDirectories);

        // Verify files are still there
        assertTrue(Files.exists(testFile1));
        assertTrue(Files.exists(testFile2));
        assertEquals("test content 1", Files.readString(testFile1));
        assertEquals("test content 2", Files.readString(testFile2));
    }

    @Test
    void isDeploymentDirectoryExistsShouldReturnCorrectStatus(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Initially should not exist
        assertFalse(structure.isDeploymentDirectoryExists());

        // After creating directories
        structure.ensureDirectories();
        assertTrue(structure.isDeploymentDirectoryExists());
    }

    @Test
    void cleanDeploymentDirectoryShouldRemoveAndRecreate(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Create directories and some test files
        structure.ensureDirectories();
        Path testFile1 = structure.getDataDir().resolve("test1.json");
        Path testFile2 = structure.getBadgesDir().resolve("test2.json");
        Path testFile3 = structure.getApiDir().resolve("test3.json");
        Files.writeString(testFile1, "test content 1");
        Files.writeString(testFile2, "test content 2");
        Files.writeString(testFile3, "test content 3");

        // Verify files exist
        assertTrue(Files.exists(testFile1));
        assertTrue(Files.exists(testFile2));
        assertTrue(Files.exists(testFile3));

        // Clean deployment directory
        structure.cleanDeploymentDirectory();

        // Verify directories exist but files are gone
        assertTrue(Files.exists(structure.getDeploymentDir()));
        assertTrue(Files.exists(structure.getDataDir()));
        assertTrue(Files.exists(structure.getBadgesDir()));
        assertTrue(Files.exists(structure.getApiDir()));
        assertFalse(Files.exists(testFile1));
        assertFalse(Files.exists(testFile2));
        assertFalse(Files.exists(testFile3));
    }

    @Test
    void cleanDeploymentDirectoryShouldWorkWhenDirectoryDoesNotExist(@TempDir Path tempDir) {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Directory doesn't exist initially
        assertFalse(Files.exists(structure.getDeploymentDir()));

        // Clean should create it
        assertDoesNotThrow(structure::cleanDeploymentDirectory);

        // Verify directories were created
        assertTrue(Files.exists(structure.getDeploymentDir()));
        assertTrue(Files.exists(structure.getDataDir()));
        assertTrue(Files.exists(structure.getBadgesDir()));
        assertTrue(Files.exists(structure.getApiDir()));
    }

    @Test
    void cleanDeploymentDirectoryShouldNotAffectNonDeploymentDirectories(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Create all directories
        structure.ensureDirectories();

        // Add files to non-deployment directories
        Path historyFile = structure.getHistoryDir().resolve("history.txt");
        Path prometheusFile = structure.getPrometheusRawDir().resolve("metrics.txt");
        Path wrkFile = structure.getWrkDir().resolve("results.txt");
        Files.writeString(historyFile, "history content");
        Files.writeString(prometheusFile, "prometheus content");
        Files.writeString(wrkFile, "wrk content");

        // Clean deployment directory
        structure.cleanDeploymentDirectory();

        // Verify non-deployment files are still there
        assertTrue(Files.exists(historyFile));
        assertTrue(Files.exists(prometheusFile));
        assertTrue(Files.exists(wrkFile));
        assertEquals("history content", Files.readString(historyFile));
        assertEquals("prometheus content", Files.readString(prometheusFile));
        assertEquals("wrk content", Files.readString(wrkFile));
    }

    @Test
    void toStringShouldContainAllPaths(@TempDir Path tempDir) {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        String toString = structure.toString();

        assertTrue(toString.contains("benchmarkResultsDir=" + benchmarkResultsDir));
        assertTrue(toString.contains("deploymentDir=" + benchmarkResultsDir.resolve("gh-pages-ready")));
        assertTrue(toString.contains("dataDir=" + benchmarkResultsDir.resolve("gh-pages-ready/data")));
        assertTrue(toString.contains("badgesDir=" + benchmarkResultsDir.resolve("gh-pages-ready/badges")));
        assertTrue(toString.contains("apiDir=" + benchmarkResultsDir.resolve("gh-pages-ready/api")));
        assertTrue(toString.contains("historyDir=" + benchmarkResultsDir.resolve("history")));
        assertTrue(toString.contains("prometheusRawDir=" + benchmarkResultsDir.resolve("prometheus")));
        assertTrue(toString.contains("wrkDir=" + benchmarkResultsDir.resolve("wrk")));
    }

    @Test
    void ensureDirectoriesShouldHandleDeepPathHierarchy(@TempDir Path tempDir) throws Exception {
        Path deepPath = tempDir.resolve("level1/level2/level3/benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(deepPath);

        // Should create all parent directories as needed
        assertDoesNotThrow(structure::ensureDirectories);

        // Verify all directories exist
        assertTrue(Files.exists(structure.getDeploymentDir()));
        assertTrue(Files.exists(structure.getDataDir()));
        assertTrue(Files.exists(structure.getBadgesDir()));
        assertTrue(Files.exists(structure.getApiDir()));
        assertTrue(Files.exists(structure.getHistoryDir()));
        assertTrue(Files.exists(structure.getPrometheusRawDir()));
        assertTrue(Files.exists(structure.getWrkDir()));
    }

    @Test
    void pathResolutionShouldBeConsistent(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // HTML dir should be same as deployment dir
        assertEquals(structure.getDeploymentDir(), structure.getHtmlDir());

        // Data, badges, and API dirs should be under deployment dir
        assertEquals(structure.getDeploymentDir().resolve("data"), structure.getDataDir());
        assertEquals(structure.getDeploymentDir().resolve("badges"), structure.getBadgesDir());
        assertEquals(structure.getDeploymentDir().resolve("api"), structure.getApiDir());

        // Non-deployed dirs should be under benchmark results root, not deployment
        assertEquals(benchmarkResultsDir.resolve("history"), structure.getHistoryDir());
        assertEquals(benchmarkResultsDir.resolve("prometheus"), structure.getPrometheusRawDir());
        assertEquals(benchmarkResultsDir.resolve("wrk"), structure.getWrkDir());
    }
}