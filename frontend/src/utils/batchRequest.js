// Helpers for firing many sequential API calls from a batch action (bulk
// assign/dissolve) without tripping nginx's per-IP rate limit
// (api_limit: 30r/s, burst 50 - see nginx/default.conf). A large batch (e.g.
// assigning 100+ iPads) fired back-to-back with no pacing exhausts that
// burst allowance in well under a second, and once it's empty EVERY request
// from that IP gets an immediate 429 - including unrelated reload calls that
// happen to land in the same window.

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Conservative spacing so a single browser tab stays well under 30r/s even
// with some jitter/other concurrent traffic from the same IP.
export const BATCH_REQUEST_DELAY_MS = 60;

/**
 * Run `fn` (an async function that performs one API call) with a couple of
 * retries specifically for HTTP 429 (rate limited) - a transient condition,
 * not a real failure. Any other error (e.g. "iPad already assigned") is
 * thrown immediately without retrying, since retrying wouldn't help.
 */
export async function withRateLimitRetry(fn, { retries = 3, baseDelayMs = 500 } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (error.response?.status === 429 && attempt < retries) {
        await sleep(baseDelayMs * (attempt + 1));
        continue;
      }
      throw error;
    }
  }
}

/** True if this axios error is an HTTP 429 (rate limited by nginx or the API itself). */
export const isRateLimitError = (error) => error?.response?.status === 429;
