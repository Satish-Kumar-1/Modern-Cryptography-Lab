import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
afterEach(cleanup);
// Canvas animations are checked in Chromium; jsdom has no drawing backend.
beforeEach(() => {
  if (typeof HTMLCanvasElement !== "undefined")
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockImplementation(
      () => null,
    );
});
vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);
vi.stubGlobal(
  "IntersectionObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);
if (typeof Element !== "undefined") {
  Element.prototype.animate = (() => ({
    finished: Promise.resolve(),
    cancel() {},
    play() {},
    pause() {},
    finish() {},
    addEventListener() {},
    removeEventListener() {},
  })) as unknown as typeof Element.prototype.animate;
}
if (typeof window !== "undefined")
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: () => ({
      matches: true,
      media: "",
      onchange: null,
      addListener() {},
      removeListener() {},
      addEventListener() {},
      removeEventListener() {},
      dispatchEvent() {
        return true;
      },
    }),
  });
