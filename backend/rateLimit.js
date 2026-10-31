// Tiny in-memory rate limiter for /api/analyze. No dependency.
// Key: client IP (Express req.ip, which respects 'trust proxy').
// Generous defaults so normal demo use never trips it.
'use strict';

function createRateLimiter(options) {
  var windowMs = (options && options.windowMs) || 15 * 60 * 1000;
  var max = (options && options.max) || 100;
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
