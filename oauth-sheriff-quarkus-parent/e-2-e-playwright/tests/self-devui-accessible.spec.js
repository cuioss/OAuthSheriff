/**
 * @fileoverview Self-tests that validate the E2E test environment
 * These are gate-keeper tests: if they fail, the environment is not ready.
 */

import { test, expect } from "../fixtures/test-fixtures.js";
import { CONSTANTS } from "../utils/constants.js";
import { isDevUIAccessible } from "../utils/devui-navigation.js";

test.describe("self-devui-accessible: Environment Validation", () => {
    test("Quarkus application is accessible", async ({ page }) => {
        const response = await page.goto(CONSTANTS.URLS.BASE, {
            waitUntil: "domcontentloaded",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        expect(response).not.toBeNull();
        expect(response.status()).toBeLessThan(500);
    });

    test("Dev-UI is accessible", async ({ page }) => {
        const accessible = await isDevUIAccessible(page);
        expect(accessible).toBe(true);
    });

    test("OAuth Sheriff extension is visible in Dev-UI", async ({ page }) => {
        await page.goto(CONSTANTS.URLS.DEVUI, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });

        // The Dev-UI extensions page should mention OAuth Sheriff
        const content = await page.content();
        expect(content.toLowerCase()).toContain("oauth");
    });

    test("JWT Validation Status page is navigable", async ({ page }) => {
        const response = await page.goto(
            CONSTANTS.DEVUI_PAGES.VALIDATION_STATUS,
            {
                waitUntil: "networkidle",
                timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
            },
        );
        expect(response).not.toBeNull();
        expect(response.status()).toBeLessThan(500);
    });

    test("JWKS Endpoints page is navigable", async ({ page }) => {
        const response = await page.goto(CONSTANTS.DEVUI_PAGES.JWKS_ENDPOINTS, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        expect(response).not.toBeNull();
        expect(response.status()).toBeLessThan(500);
    });

    test("Token Debugger page is navigable", async ({ page }) => {
        const response = await page.goto(CONSTANTS.DEVUI_PAGES.TOKEN_DEBUGGER, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        expect(response).not.toBeNull();
        expect(response.status()).toBeLessThan(500);
    });

    test("Configuration page is navigable", async ({ page }) => {
        const response = await page.goto(CONSTANTS.DEVUI_PAGES.CONFIGURATION, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        expect(response).not.toBeNull();
        expect(response.status()).toBeLessThan(500);
    });

    test("JSON-RPC returns RUNTIME status (not BUILD_TIME)", async ({
        page,
    }) => {
        // Navigate to Dev-UI to establish the JSON-RPC WebSocket connection.
        await page.goto(CONSTANTS.URLS.DEVUI, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });

        // Wait for extension metadata to load (confirms WebSocket is connected
        // and SPA is fully initialized). The footer "Connected to" text may be
        // in a collapsed panel that is not visible.
        await page.getByText("JWT Token Validation").first().waitFor({
            state: "visible",
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });

        // Call the JSON-RPC method directly from browser context.
        // Bypasses Vaadin Router SPA navigation which does not reliably render
        // extension sub-pages when links are inside shadow DOM.
        const result = await page.evaluate(async () => {
            const { devui } = await import("devui");
            const response =
                await devui.jsonRPC.OAuthSheriffDevUI.getValidationStatus();
            return JSON.stringify(response);
        });

        // Verify the response does not contain BUILD_TIME placeholder data
        expect(result).not.toContain("BUILD_TIME");
    });
});
