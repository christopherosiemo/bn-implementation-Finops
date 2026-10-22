import { test as base } from "@playwright/test";

// Page-specific mocks take precedence. An accidentally unmocked external API
// or identity request is refused rather than reaching the retained stack.
export const test = base.extend<{ isolatedPresentationBoundary: void }>({
  isolatedPresentationBoundary: [
    async ({ context, baseURL }, use) => {
      if (baseURL !== "http://127.0.0.1:4177")
        throw new Error(
          "Presentation fixtures require their owned loopback server.",
        );
      await context.route("**/*", (route) => {
        if (new URL(route.request().url()).origin !== baseURL)
          return route.abort("blockedbyclient");
        return route.continue();
      });
      await use();
    },
    { auto: true },
  ],
});
