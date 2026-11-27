import { describe, expect, it } from "vitest";

describe("harnais", () => {
  it("s'exécute dans workerd, pas dans Node", () => {
    expect(typeof crypto.subtle.timingSafeEqual).toBe("function");
  });

  it("timingSafeEqual compare bien à longueur égale", () => {
    const a = new TextEncoder().encode("aaaa");
    const b = new TextEncoder().encode("aaaa");
    const c = new TextEncoder().encode("aaab");
    expect(crypto.subtle.timingSafeEqual(a, b)).toBe(true);
    expect(crypto.subtle.timingSafeEqual(a, c)).toBe(false);
  });
});
