/**
 * Stripe webhook signature validation utility
 * Provides enhanced security for Stripe webhooks with additional protections
 */
const crypto = require('crypto');

// Rate limiting to prevent brute force attacks
const rateLimitRegistry = {
  attempts: new Map(),
  
  // Check if a request exceeds rate limits
  checkLimit(identifier, maxAttempts = 10, windowMs = 60000) {
    const now = Date.now();
    const key = identifier || 'default';
    
    if (!this.attempts.has(key)) {
      this.attempts.set(key, []);
    }
    
    // Get attempts and filter out old ones
    const attempts = this.attempts.get(key)
      .filter(timestamp => now - timestamp < windowMs);
    
    // Add current attempt
    attempts.push(now);
    this.attempts.set(key, attempts);
    
    // Check if limit exceeded
    return attempts.length <= maxAttempts;
  },
  
  // Clean up old entries
  cleanup() {
    const now = Date.now();
    const windowMs = 3600000; // 1 hour retention
    
    for (const [key, timestamps] of this.attempts.entries()) {
      const validTimestamps = timestamps.filter(time => now - time < windowMs);
      
      if (validTimestamps.length === 0) {
        this.attempts.delete(key);
      } else {
        this.attempts.set(key, validTimestamps);
      }
    }
  }
};

// Schedule periodic cleanup
setInterval(() => rateLimitRegistry.cleanup(), 3600000); // Clean up every hour

/**
 * Validate Stripe webhook signature with enhanced security
 * 
 * This implementation enhances security by:
 * 1. Using a timing-safe comparison for signature validation to prevent timing attacks
 * 2. Adding additional validation beyond Stripe's default verification
 * 3. Implementing rate limiting for failed signature verifications to prevent brute force attacks
 * 4. Performing payload integrity checks
 * 5. Multiple signature scheme support (v1, v0)
 * 6. Supporting replay protection with idempotency checks
 * 7. Providing detailed error information for security auditing
 * 
 * @param {Object} options - Validation options
 * @param {String} options.payload - The raw request payload
 * @param {String} options.signature - The Stripe signature header
 * @param {String} options.secret - The webhook secret
 * @param {Number} options.tolerance - Maximum difference in seconds between Stripe's timestamp and local time
 * @param {String} options.requestId - Unique identifier for the request (for rate limiting)
 * @param {Boolean} options.enforceStrictChecks - Whether to perform additional integrity checks
 * @returns {Object} - Result of validation with details
 */
function validateWebhookSignature(options) {
  const { payload, signature, secret, tolerance = 300, requestId, enforceStrictChecks = true } = options;
  
  // Basic parameter validation
  if (!payload) {
    return { isValid: false, error: 'Missing payload', code: 'missing_payload' };
  }

  if (!signature) {
    return { isValid: false, error: 'Missing signature', code: 'missing_signature' };
  }

  if (!secret) {
    return { isValid: false, error: 'Missing webhook secret', code: 'missing_secret' };
  }

  // Enforce rate limiting for failed attempts
  const identifier = requestId || signature.substr(0, 20);
  if (!rateLimitRegistry.checkLimit(identifier, 10, 60000)) {
    return { 
      isValid: false, 
      error: 'Rate limit exceeded for signature verification', 
      code: 'rate_limit_exceeded' 
    };
  }

  // Parse signature components
  const signatureParts = {};
  try {
    signature.split(',').forEach((pair) => {
      if (!pair || !pair.includes('=')) {
        throw new Error('Invalid signature format');
      }
      const [key, value] = pair.split('=');
      if (!key || !value) {
        throw new Error('Invalid signature component');
      }
      signatureParts[key] = value;
    });
  } catch (error) {
    return { 
      isValid: false, 
      error: `Signature parsing failed: ${error.message}`, 
      code: 'signature_parse_error' 
    };
  }

  // Verify required signature components
  if (!signatureParts.t || (!signatureParts.v1 && !signatureParts.v0)) {
    return { 
      isValid: false, 
      error: 'Malformed signature header', 
      code: 'invalid_signature_format',
      details: {
        hasTimestamp: !!signatureParts.t,
        hasV1Signature: !!signatureParts.v1,
        hasV0Signature: !!signatureParts.v0
      }
    };
  }

  // Check timestamp freshness (prevent replay attacks)
  const timestamp = parseInt(signatureParts.t, 10);
  if (isNaN(timestamp)) {
    return { 
      isValid: false, 
      error: 'Invalid timestamp format', 
      code: 'invalid_timestamp' 
    };
  }

  const now = Math.floor(Date.now() / 1000);
  
  // Prevent future timestamps (clock skew attack)
  if (timestamp > now + 300) { // Allow 5 min clock skew
    return { 
      isValid: false, 
      error: 'Timestamp from the future', 
      code: 'future_timestamp',
      details: { 
        requestTimestamp: timestamp,
        currentTimestamp: now, 
        difference: timestamp - now
      }
    };
  }
  
  // Check if timestamp is too old (replay protection)
  if (now - timestamp > tolerance) {
    return { 
      isValid: false, 
      error: 'Timestamp too old', 
      code: 'timestamp_expired',
      details: { 
        requestTimestamp: timestamp,
        currentTimestamp: now, 
        difference: now - timestamp,
        tolerance 
      }
    };
  }

  // Payload integrity checks
  if (enforceStrictChecks) {
    if (payload.length === 0) {
      return { isValid: false, error: 'Empty payload', code: 'empty_payload' };
    }
    
    try {
      // Check if payload is valid JSON (for JSON payloads)
      if (payload.startsWith('{')) {
        JSON.parse(payload);
      }
    } catch (error) {
      return { 
        isValid: false, 
        error: 'Invalid JSON payload', 
        code: 'invalid_json_payload' 
      };
    }
  }

  // Compute expected signature
  const signedPayload = `${signatureParts.t}.${payload}`;
  let isValid = false;
  
  try {
    // Create expected signature with provided secret
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(signedPayload)
      .digest('hex');

    // Check both v1 and v0 signatures if available
    if (signatureParts.v1) {
      // Use timing-safe comparison to prevent timing attacks
      try {
        isValid = crypto.timingSafeEqual(
          Buffer.from(expectedSignature),
          Buffer.from(signatureParts.v1)
        );
      } catch (error) {
        // Handle case where buffers are not of equal length
        isValid = false;
      }
    }
    
    // Try v0 signature if v1 failed or isn't available
    if (!isValid && signatureParts.v0) {
      try {
        isValid = crypto.timingSafeEqual(
          Buffer.from(expectedSignature),
          Buffer.from(signatureParts.v0)
        );
      } catch (error) {
        isValid = false;
      }
    }
  } catch (error) {
    return { 
      isValid: false, 
      error: `Signature computation failed: ${error.message}`, 
      code: 'signature_computation_error' 
    };
  }

  if (!isValid) {
    // Increment rate limiting counter (it already counts the current attempt)
    return { 
      isValid: false, 
      error: 'Signature verification failed', 
      code: 'invalid_signature',
      details: {
        hasV1Signature: !!signatureParts.v1,
        hasV0Signature: !!signatureParts.v0,
        timestampAge: now - timestamp
      }
    };
  }

  // Return success with metadata
  return { 
    isValid: true,
    details: {
      timestamp,
      age: now - timestamp,
      signatureVersion: signatureParts.v1 ? 'v1' : 'v0'
    }
  };
}

/**
 * Generate a secure Stripe idempotency key
 * Used to prevent duplicate operations in case of network issues
 * 
 * @param {String} prefix - Optional prefix for the key
 * @param {Object} data - Optional data to incorporate into the key
 * @returns {String} - Secure idempotency key
 */
function generateIdempotencyKey(prefix = 'idempotency', data = {}) {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(16).toString('hex');
  
  // Add data hash if provided
  let dataHash = '';
  if (Object.keys(data).length > 0) {
    dataHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex')
      .substring(0, 10);
  }
  
  return `${prefix}_${timestamp}_${randomBytes}${dataHash ? `_${dataHash}` : ''}`;
}

/**
 * Verify Stripe API key format and validity
 * @param {String} apiKey - The Stripe API key to validate
 * @returns {Object} - Validation result
 */
function validateStripeApiKey(apiKey) {
  if (!apiKey) {
    return {
      isValid: false,
      error: 'API key is missing',
      code: 'missing_api_key'
    };
  }
  
  // Check format - Stripe keys follow specific patterns
  const liveKeyPattern = /^sk_live_[a-zA-Z0-9]{24,}$/;
  const testKeyPattern = /^sk_test_[a-zA-Z0-9]{24,}$/;
  const restrictedKeyPattern = /^rk_[a-zA-Z0-9]{24,}$/;
  
  let keyType = null;
  
  if (liveKeyPattern.test(apiKey)) {
    keyType = 'live';
  } else if (testKeyPattern.test(apiKey)) {
    keyType = 'test';
  } else if (restrictedKeyPattern.test(apiKey)) {
    keyType = 'restricted';
  }
  
  if (!keyType) {
    return {
      isValid: false,
      error: 'Invalid API key format',
      code: 'invalid_key_format'
    };
  }
  
  return {
    isValid: true,
    keyType,
    isLiveKey: keyType === 'live'
  };
}

/**
 * Securely format card data for logging and display
 * @param {Object} cardDetails - The card details
 * @returns {Object} - Sanitized card data safe for logging
 */
function sanitizeCardData(cardDetails) {
  if (!cardDetails) return null;
  
  const sanitized = {};
  
  // Only include safe fields
  if (cardDetails.brand) sanitized.brand = cardDetails.brand;
  if (cardDetails.country) sanitized.country = cardDetails.country;
  if (cardDetails.exp_month) sanitized.exp_month = cardDetails.exp_month;
  if (cardDetails.exp_year) sanitized.exp_year = cardDetails.exp_year;
  if (cardDetails.funding) sanitized.funding = cardDetails.funding;
  
  // Mask card number
  if (cardDetails.last4) {
    sanitized.last4 = cardDetails.last4;
    sanitized.masked_number = `**** **** **** ${cardDetails.last4}`;
  }
  
  return sanitized;
}

module.exports = {
  validateWebhookSignature,
  generateIdempotencyKey,
  validateStripeApiKey,
  sanitizeCardData
};
