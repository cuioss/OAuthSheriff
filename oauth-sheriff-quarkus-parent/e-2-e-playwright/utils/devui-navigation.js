/**
 * @fileoverview Dev-UI navigation helpers for Playwright tests
 * Handles navigation to Quarkus Dev-UI pages with shadow DOM awareness
 */

import { CONSTANTS } from "./constants.js";

/**
 * Map from URL slug to custom element tag name.
 * Used to wait for the web component to be defined before navigation.
 */
const SLUG_TO_ELEMENT = {
    "jwt-validation-status": "qwc-jwt-validation-status",
    "jwks-endpoints": "qwc-jwks-endpoints",
    "token-debugger": "qwc-jwt-debugger",
    configuration: "qwc-jwt-config",
};

/**
 * Navigate to a Dev-UI extension page and wait for the custom element to render.
 * Quarkus Dev-UI uses Vaadin Router + Lit web components inside shadow DOM.
 *
 * Direct URL navigation to extension sub-pages fails because:
 *   - The Vaadin Router loads routes asynchronously via JSON-RPC WebSocket
 *   - Extension component JS files are lazily imported when the menu renders
 *
 * This helper:
 *   1. Navigates to the Dev-UI main page to fully initialize the SPA
 *   2. Waits for extension metadata to load (confirming routes are registered)
 *   3. Waits for the target custom element to be defined (import complete)
 *   4. Triggers client-side navigation via history.pushState + PopStateEvent
 *
 * @param {import('@playwright/test').Page} page - Playwright page
 * @param {string} url - Full URL to navigate to
 * @param {string} [waitForSelector] - Optional CSS selector to wait for after navigation
 */
export async function navigateToDevUIPage(page, url, waitForSelector) {
    // Step 1: Navigate to the Dev-UI main page to fully initialize the SPA.
    await page.goto(CONSTANTS.URLS.DEVUI, {
        waitUntil: "networkidle",
        timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });

    // Step 2: Wait for extension cards to load. This confirms:
    //   - JSON-RPC WebSocket is connected
    //   - Extension metadata has arrived
    //   - Menu has rendered (which triggers route registration and component imports)
    await page.getByText("JWT Token Validation").first().waitFor({
        state: "visible",
        timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
    });

    // Step 3: Wait for the target custom element to be defined.
    // Extension component JS files are lazily imported when the menu renders.
    // The import is async, so the custom element may not be registered yet.
    // The Vaadin Router uses document.createElement(tagName) to instantiate
    // the component — if the element isn't defined, it creates an HTMLUnknownElement.
    const targetPath = new URL(url).pathname;
    const slug = targetPath.split("/").pop();
    const elementName = SLUG_TO_ELEMENT[slug];

    if (elementName) {
        await page.evaluate(
            async ({ el, timeoutMs }) => {
                await Promise.race([
                    customElements.whenDefined(el),
                    new Promise((_, reject) =>
                        setTimeout(
                            () =>
                                reject(
                                    new Error(
                                        `Custom element <${el}> not defined within ${timeoutMs}ms`,
                                    ),
                                ),
                            timeoutMs,
                        ),
                    ),
                ]);
            },
            { el: elementName, timeoutMs: 10_000 },
        );
    }

    // Step 4: Trigger client-side navigation via the Vaadin Router.
    // pushState updates the URL; PopStateEvent notifies the Router to re-evaluate.
    // The Router reads window.location, matches against registered routes, and
    // renders the component into the #page outlet.
    const navDebug = await page.evaluate((path) => {
        const outlet = document.querySelector("#page");
        const router = outlet?.__router;
        const routesBefore = router?.__routes?.length ?? -1;

        history.pushState({}, "", path);
        window.dispatchEvent(new PopStateEvent("popstate"));

        return {
            hasOutlet: !!outlet,
            hasRouter: !!router,
            routeCount: routesBefore,
            currentPath: window.location.pathname,
            outletChildren: outlet?.children?.length ?? 0,
            outletHTML: outlet?.innerHTML?.substring(0, 300) ?? "",
        };
    }, targetPath);
    console.log(`[navigateToDevUIPage] ${slug}:`, JSON.stringify(navDebug));

    // Step 5: Wait for the route to resolve and the component to render.
    await page.waitForTimeout(2000);

    if (waitForSelector) {
        await page.locator(waitForSelector).waitFor({
            state: "visible",
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });
    }
}

/**
 * Navigate to the JWT Validation Status page
 * @param {import('@playwright/test').Page} page
 */
export async function goToValidationStatus(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.VALIDATION_STATUS);
}

/**
 * Navigate to the JWKS Endpoints page
 * @param {import('@playwright/test').Page} page
 */
export async function goToJwksEndpoints(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.JWKS_ENDPOINTS);
}

/**
 * Navigate to the Token Debugger page
 * @param {import('@playwright/test').Page} page
 */
export async function goToTokenDebugger(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.TOKEN_DEBUGGER);
}

/**
 * Navigate to the Configuration page
 * @param {import('@playwright/test').Page} page
 */
export async function goToConfiguration(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.CONFIGURATION);
}

/**
 * Check if the Dev-UI is accessible
 * @param {import('@playwright/test').Page} page
 * @returns {Promise<boolean>}
 */
export async function isDevUIAccessible(page) {
    try {
        const response = await page.goto(CONSTANTS.URLS.DEVUI, {
            waitUntil: "domcontentloaded",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        return response !== null && response.ok();
    } catch {
        return false;
    }
}
