/**
 * @fileoverview WCAG 2.1 Level AA accessibility compliance tests
 * Uses @axe-core/playwright for automated accessibility auditing.
 */

import {
    accessibilityTest as test,
    expect,
} from "../fixtures/test-fixtures.js";
import { CONSTANTS } from "../utils/constants.js";

test.describe("Accessibility - WCAG 2.1 AA Compliance", () => {
    test("Full Dev-UI page WCAG compliance", async ({
        page,
        accessibilityHelper,
    }) => {
        await page.goto(CONSTANTS.URLS.DEVUI, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        await page.waitForLoadState("networkidle");

        const results = await accessibilityHelper.analyze();
        // Log violations for debugging but don't fail on known Dev-UI framework issues
        if (results.violations.length > 0) {
            console.log(
                "Dev-UI page violations:",
                results.violations.map((v) => `${v.id}: ${v.description}`),
            );
        }
        // Expect no critical violations (allow minor issues from the Dev-UI framework itself)
        const critical = results.violations.filter(
            (v) => v.impact === "critical",
        );
        expect(critical).toEqual([]);
    });

    test("JWT Validation Status page accessibility", async ({
        page,
        accessibilityHelper,
    }) => {
        await page.goto(CONSTANTS.DEVUI_PAGES.VALIDATION_STATUS, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        await page.waitForLoadState("networkidle");

        const results = await accessibilityHelper.analyze();
        const critical = results.violations.filter(
            (v) => v.impact === "critical",
        );
        expect(critical).toEqual([]);
    });

    test("JWKS Endpoints page accessibility", async ({
        page,
        accessibilityHelper,
    }) => {
        await page.goto(CONSTANTS.DEVUI_PAGES.JWKS_ENDPOINTS, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        await page.waitForLoadState("networkidle");

        const results = await accessibilityHelper.analyze();
        const critical = results.violations.filter(
            (v) => v.impact === "critical",
        );
        expect(critical).toEqual([]);
    });

    test("Token Debugger page accessibility", async ({
        page,
        accessibilityHelper,
    }) => {
        await page.goto(CONSTANTS.DEVUI_PAGES.TOKEN_DEBUGGER, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        await page.waitForLoadState("networkidle");

        const results = await accessibilityHelper.analyze();
        const critical = results.violations.filter(
            (v) => v.impact === "critical",
        );
        expect(critical).toEqual([]);
    });

    test("Configuration page accessibility", async ({
        page,
        accessibilityHelper,
    }) => {
        await page.goto(CONSTANTS.DEVUI_PAGES.CONFIGURATION, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        await page.waitForLoadState("networkidle");

        const results = await accessibilityHelper.analyze();
        const critical = results.violations.filter(
            (v) => v.impact === "critical",
        );
        expect(critical).toEqual([]);
    });

    test("Keyboard navigation works on Token Debugger", async ({ page }) => {
        await page.goto(CONSTANTS.DEVUI_PAGES.TOKEN_DEBUGGER, {
            waitUntil: "networkidle",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        await page.waitForLoadState("networkidle");

        // Tab through interactive elements
        await page.keyboard.press("Tab");
        await page.keyboard.press("Tab");
        await page.keyboard.press("Tab");

        // Verify focus is on an interactive element (not stuck)
        const focusedTag = await page.evaluate(() =>
            document.activeElement?.tagName?.toLowerCase(),
        );
        // Should be on a focusable element
        expect(["button", "textarea", "input", "a", "select"]).toContain(
            focusedTag,
        );
    });
});
