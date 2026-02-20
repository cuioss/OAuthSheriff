// @ts-check
const { defineConfig, devices } = require('@playwright/test');
const path = require('path');

/**
 * Read environment variables from process.env
 */
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';

/**
 * Define paths for test artifacts (following Maven standard)
 */
const TARGET_DIR = process.env.PLAYWRIGHT_OUTPUT_DIR || path.join(__dirname, 'target');
const TEST_RESULTS_DIR = process.env.TEST_RESULTS_DIR || path.join(TARGET_DIR, 'test-results');
const REPORTS_DIR = process.env.PLAYWRIGHT_REPORT_DIR || path.join(TARGET_DIR, 'playwright-report');

/**
 * Playwright Configuration for OAuth Sheriff Dev-UI E2E Tests
 * @see https://playwright.dev/docs/test-configuration
 */
module.exports = defineConfig({
  testDir: './tests',
  /* Test timeout - 60s for Dev-UI interactions */
  timeout: process.env.E2E_TIMEOUT ? parseInt(process.env.E2E_TIMEOUT) * 1000 : 60 * 1000,
  expect: {
    /* Maximum time expect() should wait for the condition to be met */
    timeout: process.env.E2E_EXPECT_TIMEOUT ? parseInt(process.env.E2E_EXPECT_TIMEOUT) * 1000 : 15000,
  },
  /* Sequential execution - all tests share a single Quarkus dev instance */
  fullyParallel: false,
  workers: 1,
  /* Fail the build on CI if you accidentally left test.only in the source code */
  forbidOnly: !!process.env.CI,
  /* Disable retries - tests should be deterministic */
  retries: 0,
  /* Reporter configuration - NO HTML reporter to prevent server */
  reporter: [
    ['json', { outputFile: path.join(TARGET_DIR, 'test-results.json') }],
    ['junit', { outputFile: path.join(TARGET_DIR, 'junit-results.xml') }],
    ['list'],
  ],
  /* Output directories for test artifacts */
  outputDir: TEST_RESULTS_DIR,
  /* Preserve output from test runs */
  preserveOutput: 'always',
  /* Shared settings for all projects */
  use: {
    /* Base URL to use in actions like `await page.goto('/')` */
    baseURL: BASE_URL,

    /* Tracing - retain on failure for efficient storage with full debugging */
    trace: process.env.PLAYWRIGHT_TRACE || 'retain-on-failure',

    /* Screenshot only on failure to reduce artifact size */
    screenshot: process.env.PLAYWRIGHT_SCREENSHOT || 'only-on-failure',

    /* Video - retain on failure for efficient storage */
    video: process.env.PLAYWRIGHT_VIDEO || 'retain-on-failure',

    /* Ignore HTTPS errors for development environments */
    ignoreHTTPSErrors: true,

    /* Browser settings */
    viewport: { width: 1920, height: 1080 },
    actionTimeout: 10000,
    navigationTimeout: 30000,
  },

  /* Chromium only - Dev-UI is primarily Chrome-based */
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1920, height: 1080 },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--ignore-certificate-errors',
          ],
        },
      },
    },
  ],
});
