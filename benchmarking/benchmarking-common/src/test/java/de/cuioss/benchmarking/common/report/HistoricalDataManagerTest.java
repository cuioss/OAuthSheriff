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
package de.cuioss.benchmarking.common.report;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HistoricalDataManager.
 */
class HistoricalDataManagerTest {

    @Test
    void archiveCurrentRun(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();

        Map<String, Object> testData = new HashMap<>();
        testData.put("test", "data");
        testData.put("value", 123);

        String commitSha = "abc123def456789";
        manager.archiveCurrentRun(testData, tempDir.toString(), commitSha);

        // Verify history directory was created
        Path historyDir = tempDir.resolve("history");
        assertTrue(Files.exists(historyDir));
        assertTrue(Files.isDirectory(historyDir));

        // Verify file was created with correct naming pattern
        List<Path> files = manager.getHistoricalFiles(historyDir);
        assertEquals(1, files.size());

        String filename = files.getFirst().getFileName().toString();
        assertTrue(filename.endsWith("-abc123de.json"), "File should end with truncated SHA");
        assertTrue(filename.matches("\\d{4}-\\d{2}-\\d{2}-T\\d{4}Z-.*\\.json"),
                "File should match timestamp pattern");

        // Verify file content
        String content = Files.readString(files.getFirst());
        assertTrue(content.contains("\"test\""));
        assertTrue(content.contains("\"data\""));
        assertTrue(content.contains("123"));
    }

    @Test
    void archiveWithNullCommitSha(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();

        Map<String, Object> testData = new HashMap<>();
        testData.put("test", "data");

        manager.archiveCurrentRun(testData, tempDir.toString(), null);

        Path historyDir = tempDir.resolve("history");
        List<Path> files = manager.getHistoricalFiles(historyDir);
        assertEquals(1, files.size());

        String filename = files.getFirst().getFileName().toString();
        assertTrue(filename.endsWith("-unknown.json"), "File should end with 'unknown' for null SHA");
    }

    @Test
    void enforceRetentionPolicy(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create 15 test files with different timestamps
        for (int i = 0; i < 15; i++) {
            String timestamp = "2025-01-%02d-T1200Z".formatted(i + 1);
            Path file = historyDir.resolve(timestamp + "-test" + i + ".json");
            Files.writeString(file, "{}");
        }

        // Verify all files exist
        assertEquals(15, Files.list(historyDir).count());

        // Enforce retention policy
        manager.enforceRetentionPolicy(historyDir);

        // Verify only 10 most recent files remain
        List<Path> remainingFiles = manager.getHistoricalFiles(historyDir);
        assertEquals(10, remainingFiles.size());

        // Verify the oldest files were deleted (files 01-05 should be gone)
        for (Path file : remainingFiles) {
            String filename = file.getFileName().toString();
            assertFalse(filename.contains("2025-01-01") ||
                    filename.contains("2025-01-02") ||
                    filename.contains("2025-01-03") ||
                    filename.contains("2025-01-04") ||
                    filename.contains("2025-01-05"),
                    "Oldest files should be deleted: " + filename);
        }
    }

    @Test
    void getHistoricalFiles(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create test files
        Files.writeString(historyDir.resolve("2025-01-15-T1200Z-abc.json"), "{}");
        Files.writeString(historyDir.resolve("2025-01-10-T1200Z-def.json"), "{}");
        Files.writeString(historyDir.resolve("2025-01-20-T1200Z-ghi.json"), "{}");
        Files.writeString(historyDir.resolve("not-a-json.txt"), "text"); // Should be ignored

        List<Path> files = manager.getHistoricalFiles(historyDir);

        // Should only return JSON files, sorted newest first
        assertEquals(3, files.size());
        assertTrue(files.getFirst().toString().contains("2025-01-20"));
        assertTrue(files.get(1).toString().contains("2025-01-15"));
        assertTrue(files.get(2).toString().contains("2025-01-10"));
    }

    @Test
    void getHistoricalFilesEmptyDirectory(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        List<Path> files = manager.getHistoricalFiles(historyDir);
        assertTrue(files.isEmpty());
    }

    @Test
    void getHistoricalFilesNonExistentDirectory(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Path historyDir = tempDir.resolve("non-existent");

        List<Path> files = manager.getHistoricalFiles(historyDir);
        assertTrue(files.isEmpty());
    }

    @Test
    void hasHistoricalData(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();

        // Test with no history directory
        assertFalse(manager.hasHistoricalData(tempDir.toString()));

        // Create history directory but empty
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);
        assertFalse(manager.hasHistoricalData(tempDir.toString()));

        // Add a JSON file
        Files.writeString(historyDir.resolve("test.json"), "{}");
        assertTrue(manager.hasHistoricalData(tempDir.toString()));
    }

    @Test
    void retentionPolicyWithExactlyTenFiles(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create exactly 10 files
        for (int i = 0; i < 10; i++) {
            String timestamp = "2025-01-%02d-T1200Z".formatted(i + 1);
            Path file = historyDir.resolve(timestamp + "-test.json");
            Files.writeString(file, "{}");
        }

        manager.enforceRetentionPolicy(historyDir);

        // All 10 files should remain
        assertEquals(10, manager.getHistoricalFiles(historyDir).size());
    }
}