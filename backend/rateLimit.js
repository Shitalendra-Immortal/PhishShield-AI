// Tiny in-memory rate limiter for /api/analyze. No dependency.
// Key: client IP (Express req.ip, which respects 'trust proxy').
// Generous defaults so normal demo use never trips it.
// The bucket map itself is bounded: without a cap, a flood of distinct
// client IPs grows it without limit (entries only expire lazily). At the
// cap the oldest bucket is evicted, so memory stays bounded and the
// limiter keeps working (an evicted IP just gets a fresh bucket).
// Accepted limitation, same as the ai-service: buckets live in memory,
// so a restart/sleep resets them; a shared store (Redis) is out of
// scope for the hackathon demo.
'use strict';

function createRateLimiter(options) {
  var windowMs = (options && options.windowMs) || 15 * 60 * 1000;
  var max = (options && options.max) || 100;
  var maxEntries = (options && options.maxEntries) || 5000;
  var hits = new Map();

  return function rateLimiter(req, res, next) {
    var now = Date.now();
    var key = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
    // Lazy cleanup of expired buckets.
    hits.forEach(function (entry, k) {
      if (entry.reset <= now) hits.delete(k);
    });
    var entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      entry = { count: 0, reset: now + windowMs };
      if (!hits.has(key) && hits.size >= maxEntries) {
        // Evict the oldest bucket (Map preserves insertion order).
        hits.delete(hits.keys().next().value);
      }
      hits.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      var retryAfter = Math.ceil((entry.reset - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({
        error: { code: 'RATE_LIMITED', message: 'Too many requests, try again later.' }
      });
    }
    return next();
  };
}

module.exports = { createRateLimiter: createRateLimiter };
