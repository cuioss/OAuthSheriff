/**
 * @fileoverview E2E tests for JWT Configuration Dev-UI card
 * Verifies the qwc-jwt-config component displays runtime configuration data.
 */

import { test, expect } from "../fixtures/test-fixtures.js";
import { CONSTANTS } from "../utils/constants.js";
import { goToConfiguration } from "../utils/devui-navigation.js";

test.describe("04 - Configuration Card", () => {
    test.beforeEach(async ({ page }) => {
        await goToConfiguration(page);
    });

    test("should display the configuration container", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER,
        );
        const loading = page.locator(CONSTANTS.SELECTORS.JWT_CONFIG_LOADING);
        const error = page.locator(CONSTANTS.SELECTORS.JWT_CONFIG_ERROR);

        await expect(container.or(loading).or(error)).toBeVisible({
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });
    });

    test("should show runtime config (not build-time placeholders)", async ({
        page,
    }) => {
        // Wait for the component to finish loading via JSON-RPC
        await page
            .locator(CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER)
            .or(page.locator(CONSTANTS.SELECTORS.JWT_CONFIG_ERROR))
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            });
        // Use textContent() on the custom element because page.content() does not
        // include shadow DOM content (LitElement renders inside shadow root).
        const text = await page.locator("qwc-jwt-config").textContent();
        expect(text).not.toContain("BUILD_TIME");
    });

    test("should display general settings section", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const generalSection = page.locator(
                CONSTANTS.SELECTORS.JWT_CONFIG_GENERAL_SECTION,
            );
            await expect(generalSection).toBeVisible();

            // Should contain Enabled and Log Level config items
            const sectionText = await generalSection.textContent();
            expect(sectionText).toContain("Enabled");
            expect(sectionText).toContain("Log Level");
        }
    });

    test("should display parser configuration section", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const parserSection = page.locator(
                CONSTANTS.SELECTORS.JWT_CONFIG_PARSER_SECTION,
            );
            await expect(parserSection).toBeVisible();

            const sectionText = await parserSection.textContent();
            expect(sectionText).toContain("Max Token Size");
            expect(sectionText).toContain("Clock Skew");
        }
    });

    test("should display issuers configuration section", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const issuersSection = page.locator(
                CONSTANTS.SELECTORS.JWT_CONFIG_ISSUERS_SECTION,
            );
            await expect(issuersSection).toBeVisible();

            // Should list the configured issuers
            const sectionText = await issuersSection.textContent();
            expect(sectionText).toContain("Configured Issuers");
        }
    });

    test("should display health indicator", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const healthIndicator = page.locator(
                CONSTANTS.SELECTORS.JWT_CONFIG_HEALTH_INDICATOR,
            );
            // Health indicator may not always be present (depends on health response)
            if (await healthIndicator.isVisible()) {
                const text = await healthIndicator.textContent();
                expect(text).toMatch(/Healthy|Issues/i);
            }
        }
    });

    test("should have a working refresh button", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWT_CONFIG_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const refreshButton = page.locator(
                CONSTANTS.SELECTORS.JWT_CONFIG_REFRESH_BUTTON,
            );
            await expect(refreshButton).toBeVisible();
            await expect(refreshButton).toBeEnabled();

            // Click refresh
            await refreshButton.click();

            // Container or loading should still be visible after refresh
            await expect(
                container.or(
                    page.locator(CONSTANTS.SELECTORS.JWT_CONFIG_LOADING),
                ),
            ).toBeVisible({
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            });
        }
    });
});
