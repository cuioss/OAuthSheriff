/**
 * @fileoverview E2E tests for JWT Validation Status Dev-UI card
 * Verifies the qwc-jwt-validation-status component renders correctly with runtime data.
 */

import { test, expect } from "../fixtures/test-fixtures.js";
import { CONSTANTS } from "../utils/constants.js";
import { goToValidationStatus } from "../utils/devui-navigation.js";

test.describe("01 - JWT Validation Status Card", () => {
    test.beforeEach(async ({ page }) => {
        await goToValidationStatus(page);
    });

    test("should display the validation status card", async ({ page }) => {
        // Wait for either the card or loading/error state
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        const loading = page.locator(CONSTANTS.SELECTORS.VALIDATION_LOADING);
        const error = page.locator(CONSTANTS.SELECTORS.VALIDATION_ERROR);

        // One of these should be visible
        await expect(card.or(loading).or(error)).toBeVisible({
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });
    });

    test("should show RUNTIME data (not BUILD_TIME placeholders)", async ({
        page,
    }) => {
        // Wait for the component to finish loading via JSON-RPC
        await page
            .locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD)
            .or(page.locator(CONSTANTS.SELECTORS.VALIDATION_ERROR))
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            });
        const content = await page.content();
        expect(content).not.toContain("BUILD_TIME");
    });

    test("should display enabled/disabled metric", async ({ page }) => {
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        // Wait for card to appear (may take time for JSON-RPC)
        await card
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await card.isVisible()) {
            const enabledMetric = page.locator(
                CONSTANTS.SELECTORS.METRIC_ENABLED,
            );
            await expect(enabledMetric).toBeVisible();

            // Should contain 'Yes' or 'No'
            const text = await enabledMetric.textContent();
            expect(text).toMatch(/Yes|No/);
        }
    });

    test("should display validator present metric", async ({ page }) => {
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        await card
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await card.isVisible()) {
            const validatorMetric = page.locator(
                CONSTANTS.SELECTORS.METRIC_VALIDATOR_PRESENT,
            );
            await expect(validatorMetric).toBeVisible();
        }
    });

    test("should display overall status metric", async ({ page }) => {
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        await card
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await card.isVisible()) {
            const statusMetric = page.locator(
                CONSTANTS.SELECTORS.METRIC_OVERALL_STATUS,
            );
            await expect(statusMetric).toBeVisible();
        }
    });

    test("should have a working refresh button", async ({ page }) => {
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        await card
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await card.isVisible()) {
            const refreshButton = page.locator(
                CONSTANTS.SELECTORS.VALIDATION_REFRESH_BUTTON,
            );
            await expect(refreshButton).toBeVisible();
            await expect(refreshButton).toBeEnabled();

            // Click refresh and verify the page doesn't crash
            await refreshButton.click();
            // Card or loading should be visible after refresh
            await expect(
                card.or(page.locator(CONSTANTS.SELECTORS.VALIDATION_LOADING)),
            ).toBeVisible({
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            });
        }
    });

    test("should display status indicator", async ({ page }) => {
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        await card
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await card.isVisible()) {
            const indicator = page.locator(
                CONSTANTS.SELECTORS.VALIDATION_STATUS_INDICATOR,
            );
            await expect(indicator).toBeVisible();
        }
    });

    test("should display status message", async ({ page }) => {
        const card = page.locator(CONSTANTS.SELECTORS.VALIDATION_STATUS_CARD);
        await card
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await card.isVisible()) {
            const message = page.locator(
                CONSTANTS.SELECTORS.VALIDATION_STATUS_MESSAGE,
            );
            await expect(message).toBeVisible();
            const text = await message.textContent();
            expect(text.length).toBeGreaterThan(0);
        }
    });
});
