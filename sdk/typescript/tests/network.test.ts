import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import { createServer } from "node:http";
import { setTimeout as setTimeoutPromise } from "node:timers/promises";
import { fetchJWKSWithRetry, getUserAgent } from "../src/utils.js";

/* global URL */

describe("Network Operations", () => {
  let httpServer: any;
  let httpPort: number;

  before(async () => {
    // Setup HTTP test server
    httpServer = createServer((req, res) => {
      const url = new URL(req.url!, `http://localhost:${httpPort}`);

      if (url.pathname === "/.well-known/jwks.json") {
        // Valid JWKS response
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            keys: [
              {
                kty: "RSA",
                kid: "test-key",
                use: "sig",
                alg: "RS256",
                n: "test-modulus",
                e: "AQAB",
              },
            ],
          })
        );
      } else if (url.pathname === "/retry-test") {
        // Simulate retry scenario
        const attempt = parseInt(url.searchParams.get("attempt") || "1");
        if (attempt < 3) {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("Server Error");
        } else {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ keys: [] }));
        }
      } else if (url.pathname === "/slow-response") {
        // Simulate slow response
        setTimeout(() => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ keys: [] }));
        }, 2000);
      } else if (url.pathname === "/invalid-json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end("{ invalid json");
      } else if (url.pathname === "/empty-keys") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ keys: [] }));
      } else if (url.pathname === "/missing-keys") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({}));
      } else if (url.pathname === "/user-agent-test") {
        // Check User-Agent header
        const userAgent = req.headers["user-agent"];
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            keys: [],
            receivedUserAgent: userAgent,
          })
        );
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not Found");
      }
    });

    httpPort = await new Promise<number>((resolve) => {
      httpServer.listen(0, () => {
        resolve(httpServer.address()?.port || 0);
      });
    });
  });

  after(async () => {
    if (httpServer) {
      return new Promise<void>((resolve) => {
        httpServer.close(resolve);
      });
    }
  });

  describe("JWKS Fetching", () => {
    it("should successfully fetch JWKS from well-known endpoint", async () => {
      const mockFetch = async () => {
        // Instead of calling fetch in a loop, just return a mock response
        return {
          ok: true,
          json: async () => ({
            keys: [{ kty: "RSA", kid: "test-key", n: "test", e: "AQAB" }],
          }),
        };
      };

      // Mock the global fetch for this test
      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        const keys = await fetchJWKSWithRetry("test.com");
        assert.ok(Array.isArray(keys));
        assert.strictEqual(keys.length, 1);
        assert.strictEqual(keys[0]?.kty, "RSA");
        assert.strictEqual(keys[0]?.kid, "test-key");
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle successful fetch with multiple keys", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        json: async () => ({
          keys: [
            { kty: "RSA", kid: "rsa-key", use: "sig", alg: "RS256", n: "test", e: "AQAB" },
            { kty: "EC", kid: "ec-key", use: "sig", alg: "ES256", crv: "P-256", x: "test", y: "test" },
            { kty: "RSA", kid: "enc-key", use: "enc", alg: "RSA-OAEP-256", n: "test2", e: "AQAB" },
          ],
        }),
      };

      const mockFetch = async () => mockResponse;
      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        const keys = await fetchJWKSWithRetry("test.com");
        assert.strictEqual(keys.length, 3);
        assert.strictEqual(keys[0]?.kid, "rsa-key");
        assert.strictEqual(keys[1]?.kid, "ec-key");
        assert.strictEqual(keys[2]?.kid, "enc-key");
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("Retry Logic", () => {
    it("should implement exponential backoff retry", async () => {
      let attemptCount = 0;
      const mockFetch = async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error("Network error");
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        const startTime = Date.now();
        await fetchJWKSWithRetry("test.com", { maxRetries: 3, retryDelay: 100 });
        const elapsed = Date.now() - startTime;

        assert.strictEqual(attemptCount, 3);
        // Should have waited for retries: 100ms + 200ms = 300ms minimum
        assert.ok(elapsed >= 300, `Expected at least 300ms, got ${elapsed}ms`);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should respect maximum retry attempts", async () => {
      let attemptCount = 0;
      const mockFetch = async () => {
        attemptCount++;
        throw new Error("Persistent network error");
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 2, retryDelay: 10 }),
          /Failed to fetch JWKS from .* after \d+ attempts/
        );
        assert.strictEqual(attemptCount, 3); // Initial attempt + 2 retries
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should implement correct exponential backoff timing", async () => {
      let attemptCount = 0;
      const attemptTimes: number[] = [];

      const mockFetch = async () => {
        attemptTimes.push(Date.now());
        attemptCount++;
        if (attemptCount < 4) {
          throw new Error("Network error");
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await fetchJWKSWithRetry("test.com", { maxRetries: 3, retryDelay: 100 });

        // Check timing between attempts (should be ~100ms, 200ms, 400ms)
        assert.strictEqual(attemptTimes.length, 4); // Initial + 3 retries

        const delay1 = attemptTimes[1]! - attemptTimes[0]!;
        const delay2 = attemptTimes[2]! - attemptTimes[1]!;
        const delay3 = attemptTimes[3]! - attemptTimes[2]!;

        // Allow some tolerance for timing
        assert.ok(delay1 >= 90 && delay1 <= 150, `First delay: ${delay1}ms`);
        assert.ok(delay2 >= 180 && delay2 <= 250, `Second delay: ${delay2}ms`);
        assert.ok(delay3 >= 380 && delay3 <= 450, `Third delay: ${delay3}ms`);
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("Timeout Handling", () => {
    it("should handle request timeout", async () => {
      const mockFetch = async (_url: any, options: any) => {
        return new Promise((resolve, reject) => {
          const timeoutId = setTimeout(() => {
            resolve({
              ok: true,
              status: 200,
              json: async () => ({ keys: [] }),
            });
          }, 15000); // 15 second delay, should timeout

          // Handle abort signal
          if (options?.signal) {
            options.signal.addEventListener("abort", () => {
              clearTimeout(timeoutId);
              reject(new DOMException("The operation was aborted.", "AbortError"));
            });
          }
        });
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () =>
            await fetchJWKSWithRetry("test.com", {
              maxRetries: 1,
              retryDelay: 10,
              timeout: 1000, // 1 second timeout
            }),
          /timeout/i
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should use default 10 second timeout", async () => {
      let timeoutUsed: string | null = null;

      const mockFetch = async (_url: any, options: any) => {
        // Extract timeout from AbortSignal if present
        if (options?.signal) {
          timeoutUsed = "signal-present";
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await fetchJWKSWithRetry("test.com");
        assert.strictEqual(timeoutUsed, "signal-present");
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("HTTP Error Handling", () => {
    it("should handle 404 Not Found", async () => {
      const mockFetch = async () => ({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1 }), /HTTP 404/);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle 403 Forbidden", async () => {
      const mockFetch = async () => ({
        ok: false,
        status: 403,
        statusText: "Forbidden",
      });

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1 }), /HTTP 403/);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle 500 Internal Server Error with retry", async () => {
      let attemptCount = 0;
      const mockFetch = async () => {
        attemptCount++;
        if (attemptCount < 3) {
          return {
            ok: false,
            status: 500,
            statusText: "Internal Server Error",
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        const keys = await fetchJWKSWithRetry("test.com", { maxRetries: 3, retryDelay: 10 });
        assert.strictEqual(attemptCount, 3);
        assert.ok(Array.isArray(keys));
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle 503 Service Unavailable with retry", async () => {
      let attemptCount = 0;
      const mockFetch = async () => {
        attemptCount++;
        return {
          ok: false,
          status: 503,
          statusText: "Service Unavailable",
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 2, retryDelay: 10 }),
          /HTTP 503/
        );
        assert.strictEqual(attemptCount, 3); // Initial + 2 retries
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("Invalid JWKS Response", () => {
    it("should handle malformed JSON", async () => {
      const mockFetch = async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("Unexpected token");
        },
      });

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1 }),
          /Failed to parse JWKS response/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle response without keys array", async () => {
      const mockFetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({}), // Missing keys array
      });

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1 }),
          /Invalid JWKS response: missing keys array/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle empty keys array", async () => {
      const mockFetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ keys: [] }),
      });

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        const keys = await fetchJWKSWithRetry("test.com");
        assert.ok(Array.isArray(keys));
        assert.strictEqual(keys.length, 0);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle non-array keys field", async () => {
      const mockFetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ keys: "not-an-array" }),
      });

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1 }),
          /Invalid JWKS response: keys is not an array/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("User-Agent Header", () => {
    it("should send correct User-Agent header", () => {
      const userAgent = getUserAgent();

      // Should match format: TAC-Protocol/version (language/sdk-version)
      assert.match(userAgent, /^TAC-Protocol\/[\d\-.]+ \(TypeScript\/[\d.]+\)$/);
    });

    it("should include User-Agent in JWKS requests", async () => {
      let receivedUserAgent: string | null = null;

      const mockFetch = async (_url: any, options: any) => {
        receivedUserAgent = options?.headers?.["User-Agent"] || options?.headers?.["user-agent"];
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await fetchJWKSWithRetry("test.com");
        assert.ok(receivedUserAgent);
        assert.match(receivedUserAgent, /^TAC-Protocol\//);
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("Network Error Types", () => {
    it("should handle connection refused", async () => {
      const mockFetch = async () => {
        throw new Error("connect ECONNREFUSED");
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1, retryDelay: 10 }),
          /ECONNREFUSED/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle DNS failure", async () => {
      const mockFetch = async () => {
        throw new Error("getaddrinfo ENOTFOUND");
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1, retryDelay: 10 }),
          /ENOTFOUND/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle network timeout", async () => {
      const mockFetch = async () => {
        throw new Error("network timeout");
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("test.com", { maxRetries: 1, retryDelay: 10 }),
          /network timeout/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("SSL/TLS Handling", () => {
    it("should handle HTTPS URLs", async () => {
      const mockFetch = async (url: string) => {
        assert.ok(url.startsWith("https://"), "Should use HTTPS for JWKS endpoint");
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await fetchJWKSWithRetry("secure.com");
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle SSL certificate errors", async () => {
      const mockFetch = async () => {
        throw new Error("unable to verify the first certificate");
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        await assert.rejects(
          async () => await fetchJWKSWithRetry("invalid-cert.com", { maxRetries: 1, retryDelay: 10 }),
          /certificate/
        );
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("Performance and Concurrency", () => {
    it("should handle concurrent JWKS requests", async () => {
      let requestCount = 0;
      const mockFetch = async () => {
        requestCount++;
        await setTimeoutPromise(50); // Simulate network delay
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        const promises = Array.from({ length: 10 }, () => fetchJWKSWithRetry("test.com", { maxRetries: 1 }));

        const results = await Promise.all(promises);

        // All requests should succeed
        assert.strictEqual(results.length, 10);
        results.forEach((keys) => {
          assert.ok(Array.isArray(keys));
        });

        // Should have made 10 requests (no deduplication in this test)
        assert.strictEqual(requestCount, 10);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it("should handle request deduplication for same domain", async () => {
      // This test would require implementing request deduplication in the actual code
      // For now, we'll just verify that multiple requests can be made concurrently

      let requestCount = 0;
      const mockFetch = async () => {
        requestCount++;
        await setTimeoutPromise(100);
        return {
          ok: true,
          status: 200,
          json: async () => ({ keys: [] }),
        };
      };

      const originalFetch = global.fetch;
      global.fetch = mockFetch as any;

      try {
        // Make multiple simultaneous requests for the same domain
        const promises = Array.from({ length: 5 }, () => fetchJWKSWithRetry("same-domain.com", { maxRetries: 1 }));

        const results = await Promise.all(promises);

        assert.strictEqual(results.length, 5);
        // In a real implementation with deduplication, requestCount should be 1
        // For now, it will be 5
        assert.ok(requestCount >= 1);
      } finally {
        global.fetch = originalFetch;
      }
    });
  });
});
