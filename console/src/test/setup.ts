import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// jsdom does not lay anything out, so it has no scrollIntoView.
Element.prototype.scrollIntoView = () => undefined;

afterEach(() => {
  cleanup();
});
