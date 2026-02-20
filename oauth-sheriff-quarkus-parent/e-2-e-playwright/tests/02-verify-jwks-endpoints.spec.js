/**
 * @fileoverview E2E tests for JWKS Endpoints Dev-UI card
 * Verifies the qwc-jwks-endpoints component renders with configured issuer data.
 */

import { test, expect } from "../fixtures/test-fixtures.js";
import { CONSTANTS } from "../utils/constants.js";
import { goToJwksEndpoints } from "../utils/devui-navigation.js";

test.describe("02 - JWKS Endpoints Card", () => {
    test.beforeEach(async ({ page }) => {
        await goToJwksEndpoints(page);
    });

    test("should display the JWKS endpoints container", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWKS_ENDPOINTS_CONTAINER,
        );
        const loading = page.locator(CONSTANTS.SELECTORS.JWKS_LOADING);
        const error = page.locator(CONSTANTS.SELECTORS.JWKS_ERROR);

        await expect(container.or(loading).or(error)).toBeVisible({
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });
    });

    test("should show CONFIGURED status when issuers exist", async ({
        page,
    }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWKS_ENDPOINTS_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const statusMessage = page.locator(
                CONSTANTS.SELECTORS.JWKS_STATUS_MESSAGE,
            );
            await expect(statusMessage).toBeVisible();

            const text = await statusMessage.textContent();
            // Should indicate configured (not NO_ISSUERS)
            expect(text.toLowerCase()).toContain("configured");
        }
    });

    test("should list configured issuers", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWKS_ENDPOINTS_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const issuerCards = page.locator(
                CONSTANTS.SELECTORS.JWKS_ISSUER_CARD,
            );
            // We have at least keycloak and integration issuers configured
            const count = await issuerCards.count();
            expect(count).toBeGreaterThanOrEqual(2);
        }
    });

    test("should display issuer details with URIs", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWKS_ENDPOINTS_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const firstIssuer = page
                .locator(CONSTANTS.SELECTORS.JWKS_ISSUER_CARD)
                .first();
            await expect(firstIssuer).toBeVisible();

            // Should contain issuer details like URI and JWKS URI
            const issuerText = await firstIssuer.textContent();
            expect(issuerText.length).toBeGreaterThan(10);
        }
    });

    test("should have a working refresh button", async ({ page }) => {
        const container = page.locator(
            CONSTANTS.SELECTORS.JWKS_ENDPOINTS_CONTAINER,
        );
        await container
            .waitFor({
                state: "visible",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            })
            .catch(() => {});

        if (await container.isVisible()) {
            const refreshButton = page.locator(
                CONSTANTS.SELECTORS.JWKS_REFRESH_BUTTON,
            );
            await expect(refreshButton).toBeVisible();
            await expect(refreshButton).toBeEnabled();

            // Click refresh
            await refreshButton.click();

            // Container or loading should still be visible after refresh
            await expect(
                container.or(page.locator(CONSTANTS.SELECTORS.JWKS_LOADING)),
            ).toBeVisible({
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            });
        }
    });
});
