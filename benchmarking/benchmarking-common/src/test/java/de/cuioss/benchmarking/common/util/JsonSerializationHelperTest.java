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
package de.cuioss.benchmarking.common.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonSerializationHelperTest {

    @TempDir
    Path tempDir;

    @Test
    void formatDouble() {
        // Test whole numbers
        assertEquals("42", JsonSerializationHelper.formatDouble(42.0));
        assertEquals("100", JsonSerializationHelper.formatDouble(100.0));
        assertEquals("0", JsonSerializationHelper.formatDouble(0.0));
        assertEquals("-10", JsonSerializationHelper.formatDouble(-10.0));

        // Test decimal numbers - locale-dependent formatting
        String formatted425 = JsonSerializationHelper.formatDouble(42.5);
        assertTrue("42.50".equals(formatted425) || "42,50".equals(formatted425));

        String formatted314 = JsonSerializationHelper.formatDouble(3.14159);
        assertTrue("3.14".equals(formatted314) || "3,14".equals(formatted314));

        String formattedNeg275 = JsonSerializationHelper.formatDouble(-2.75);
        assertTrue("-2.75".equals(formattedNeg275) || "-2,75".equals(formattedNeg275));

        String formatted01 = JsonSerializationHelper.formatDouble(0.1);
        assertTrue("0.10".equals(formatted01) || "0,10".equals(formatted01));
    }

    @Test
    void writeAndReadJsonFile() throws Exception {
        // Create test data
        Map<String, Object> testData = new HashMap<>();
        testData.put("name", "test");
        testData.put("value", 42);
        testData.put("flag", true);

        // Write to file
        Path jsonFile = tempDir.resolve("test.json");
        JsonSerializationHelper.writeJsonFile(jsonFile, testData);

        // Verify file exists
        assertTrue(Files.exists(jsonFile));

        // Read back as Map
        @SuppressWarnings("unchecked") Map<String, Object> readData = JsonSerializationHelper.readJsonFile(jsonFile, Map.class);

        assertNotNull(readData);
        assertEquals("test", readData.get("name"));
        assertEquals(42.0, readData.get("value")); // Gson reads numbers as doubles
        assertEquals(true, readData.get("flag"));
    }

    @Test
    void writeJsonFileCreatesDirectories() throws Exception {
        // Create nested path
        Path nestedFile = tempDir.resolve("nested/dir/structure/data.json");

        // Write data
        String testData = "test content";
        JsonSerializationHelper.writeJsonFile(nestedFile, testData);

        // Verify directories were created
        assertTrue(Files.exists(nestedFile.getParent()));
        assertTrue(Files.exists(nestedFile));

        // Read back
        String readData = JsonSerializationHelper.readJsonFile(nestedFile, String.class);
        assertEquals(testData, readData);
    }

    @Test
    void gsonConfiguration() {
        // Test that GSON is properly configured
        assertNotNull(JsonSerializationHelper.GSON);

        // Test pretty printing
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");
        String json = JsonSerializationHelper.GSON.toJson(data);
        assertTrue(json.contains("\n")); // Pretty printing adds newlines

        // Test Double serialization
        Double wholeNumber = 42.0;
        String wholeJson = JsonSerializationHelper.GSON.toJson(wholeNumber);
        assertEquals("42", wholeJson);

        Double decimal = 42.5;
        String decimalJson = JsonSerializationHelper.GSON.toJson(decimal);
        assertEquals("42.5", decimalJson);

        // Test Instant serialization
        Instant now = Instant.parse("2025-01-15T10:30:00Z");
        String instantJson = JsonSerializationHelper.GSON.toJson(now);
        assertEquals("\"2025-01-15T10:30:00Z\"", instantJson);
    }

    @Test
    void complexObjectSerialization() throws Exception {
        // Create complex object without Instant (causes issues with Gson)
        TestObject obj = new TestObject();
        obj.id = 1;
        obj.name = "Test Object";
        obj.value = 99.99;
        obj.wholeValue = 100.0;
        obj.timestampString = "2025-01-15T12:00:00Z";
        obj.active = true;

        // Write and read
        Path file = tempDir.resolve("complex.json");
        JsonSerializationHelper.writeJsonFile(file, obj);

        TestObject readObj = JsonSerializationHelper.readJsonFile(file, TestObject.class);

        assertNotNull(readObj);
        assertEquals(obj.id, readObj.id);
        assertEquals(obj.name, readObj.name);
        assertEquals(obj.value, readObj.value);
        assertEquals(obj.wholeValue, readObj.wholeValue);
        assertEquals(obj.timestampString, readObj.timestampString);
        assertEquals(obj.active, readObj.active);
    }

    @Test
    void nullHandling() {
        // Test null Double serialization
        Double nullDouble = null;
        String nullJson = JsonSerializationHelper.GSON.toJson(nullDouble);
        assertEquals("null", nullJson);

        // Test null Instant serialization
        Instant nullInstant = null;
        String nullInstantJson = JsonSerializationHelper.GSON.toJson(nullInstant);
        assertEquals("null", nullInstantJson);
    }

    @Test
    void readNonExistentFile() {
        Path nonExistent = tempDir.resolve("does-not-exist.json");

        assertThrows(IOException.class, () ->
                JsonSerializationHelper.readJsonFile(nonExistent, Map.class)
        );
    }

    @Test
    void specialDoubleValues() {
        // Test special double values
        assertEquals("0", JsonSerializationHelper.formatDouble(0.0));
        // Note: -0.0 becomes 0 when converted to long, which is acceptable behavior
        assertEquals("0", JsonSerializationHelper.formatDouble(-0.0));
        assertEquals("1000000", JsonSerializationHelper.formatDouble(1_000_000.0));

        // For very small values < 1, formatDouble uses %.2f format
        String formatted = JsonSerializationHelper.formatDouble(0.001);
        assertTrue("0.00".equals(formatted) || "0,00".equals(formatted));
    }

    // Test helper class
    static class TestObject {
        int id;
        String name;
        Double value;
        Double wholeValue;
        String timestampString;
        boolean active;
    }
}