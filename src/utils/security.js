const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Password utility functions
const passwordUtils = {
  // Generate a secure random password
  generateSecurePassword: (length = 12) => {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    // Ensure at least one character from each required category
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];
    
    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
  },

  // Calculate password strength score (0-100)
  calculateStrength: (password) => {
    let score = 0;
    
    // Length bonus
    if (password.length >= 8) score += 25;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;
    
    // Character variety bonus
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^A-Za-z0-9]/.test(password)) score += 10;
    
    // Pattern penalties
    if (/(.)\1{2,}/.test(password)) score -= 10; // Repeated characters
    if (/123|abc|qwe/i.test(password)) score -= 5; // Sequential patterns
    
    // Dictionary word penalty (simple check)
    const commonWords = ['password', 'admin', 'user', 'login', 'welcome'];
    if (commonWords.some(word => password.toLowerCase().includes(word))) {
      score -= 20;
    }
    
    return Math.max(0, Math.min(100, score));
  },

  // Get password strength feedback
  getStrengthFeedback: (password) => {
    const score = passwordUtils.calculateStrength(password);
    const feedback = {
      score,
      level: '',
      suggestions: []
    };
    
    if (score < 30) {
      feedback.level = 'Very Weak';
      feedback.suggestions.push('Use at least 8 characters');
      feedback.suggestions.push('Include uppercase and lowercase letters');
      feedback.suggestions.push('Add numbers and special characters');
    } else if (score < 50) {
      feedback.level = 'Weak';
      feedback.suggestions.push('Consider using more characters');
      feedback.suggestions.push('Avoid common words and patterns');
    } else if (score < 70) {
      feedback.level = 'Fair';
      feedback.suggestions.push('Consider adding more character variety');
    } else if (score < 85) {
      feedback.level = 'Good';
    } else {
      feedback.level = 'Strong';
    }
    
    return feedback;
  }
};

// Encryption utilities
const encryptionUtils = {
  // Encrypt data using AES-256-GCM
  encrypt: (text, key = null) => {
    const algorithm = 'aes-256-gcm';
    const secretKey = key || process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key-12';
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher(algorithm, secretKey);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      encrypted,
      authTag: authTag.toString('hex')
    };
  },

  // Decrypt data
  decrypt: (encryptedData, key = null) => {
    const algorithm = 'aes-256-gcm';
    const secretKey = key || process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key-12';
    
    const decipher = crypto.createDecipher(algorithm, secretKey);
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  },

  // Generate hash with salt
  hashWithSalt: (data, saltRounds = 12) => {
    return bcrypt.hashSync(data, saltRounds);
  },

  // Verify hash
  verifyHash: (data, hash) => {
    return bcrypt.compareSync(data, hash);
  },

  // Generate HMAC
  generateHMAC: (data, secret) => {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
  },

  // Verify HMAC
  verifyHMAC: (data, secret, providedHMAC) => {
    const computedHMAC = encryptionUtils.generateHMAC(data, secret);
    return crypto.timingSafeEqual(Buffer.from(computedHMAC), Buffer.from(providedHMAC));
  }
};

// Security utilities
const securityUtils = {
  // Generate secure random token
  generateSecureToken: (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
  },

  // Generate cryptographically secure random string
  generateSecureString: (length = 16, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') => {
    let result = '';
    const bytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
      result += charset[bytes[i] % charset.length];
    }
    
    return result;
  },

  // Sanitize input to prevent XSS
  sanitizeInput: (input) => {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/[<>]/g, '') // Remove < and >
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  },

  // Validate IP address
  isValidIP: (ip) => {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  },

  // Rate limiting helper
  createRateLimit: (windowMs, max, message) => {
    const attempts = new Map();
    
    return (identifier) => {
      const now = Date.now();
      const windowStart = now - windowMs;
      
      // Clean up old entries
      for (const [key, value] of attempts) {
        if (value.firstAttempt < windowStart) {
          attempts.delete(key);
        }
      }
      
      const userAttempts = attempts.get(identifier);
      
      if (!userAttempts) {
        attempts.set(identifier, { count: 1, firstAttempt: now });
        return { allowed: true, remaining: max - 1 };
      }
      
      if (userAttempts.firstAttempt < windowStart) {
        attempts.set(identifier, { count: 1, firstAttempt: now });
        return { allowed: true, remaining: max - 1 };
      }
      
      if (userAttempts.count >= max) {
        return { 
          allowed: false, 
          remaining: 0, 
          resetTime: userAttempts.firstAttempt + windowMs,
          message 
        };
      }
      
      userAttempts.count++;
      return { allowed: true, remaining: max - userAttempts.count };
    };
  },

  // Check for suspicious patterns
  detectSuspiciousPatterns: (input) => {
    const patterns = [
      { name: 'SQL Injection', regex: /(\b(union|select|insert|update|delete|drop|create|alter)\b|--|\/\*|\*\/|;)/i },
      { name: 'XSS', regex: /<script|javascript:|onload=|onerror=|eval\(|document\.|window\./i },
      { name: 'Path Traversal', regex: /\.\.[\/\\]|[\/\\]\.\./i },
      { name: 'Command Injection', regex: /[;&|`$(){}[\]]/i }
    ];
    
    const detected = [];
    
    patterns.forEach(pattern => {
      if (pattern.regex.test(input)) {
        detected.push(pattern.name);
      }
    });
    
    return detected;
  },

  // Generate CSRF token
  generateCSRFToken: () => {
    return crypto.randomBytes(32).toString('hex');
  },

  // Time-based one-time token (for additional security)
  generateTimeBasedToken: (secret, timeStep = 30) => {
    const time = Math.floor(Date.now() / 1000 / timeStep);
    const timeHex = time.toString(16).padStart(16, '0');
    return crypto.createHmac('sha256', secret).update(timeHex).digest('hex').slice(0, 8);
  },

  // Verify time-based token
  verifyTimeBasedToken: (token, secret, timeStep = 30, window = 1) => {
    const currentTime = Math.floor(Date.now() / 1000 / timeStep);
    
    for (let i = -window; i <= window; i++) {
      const testTime = currentTime + i;
      const timeHex = testTime.toString(16).padStart(16, '0');
      const testToken = crypto.createHmac('sha256', secret).update(timeHex).digest('hex').slice(0, 8);
      
      if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(testToken))) {
        return true;
      }
    }
    
    return false;
  }
};

// Validation utilities
const validationUtils = {
  // Email validation
  isValidEmail: (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  // Username validation
  isValidUsername: (username) => {
    const usernameRegex = /^[a-zA-Z0-9_]{3,50}$/;
    return usernameRegex.test(username);
  },

  // Phone number validation
  isValidPhoneNumber: (phone) => {
    const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
    return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10;
  },

  // Account number validation
  isValidAccountNumber: (accountNumber) => {
    const accountRegex = /^[A-Z0-9]{10,20}$/;
    return accountRegex.test(accountNumber);
  },

  // Amount validation
  isValidAmount: (amount) => {
    return !isNaN(amount) && isFinite(amount) && amount > 0 && amount <= 1000000;
  },

  // Sanitize and validate input
  sanitizeAndValidate: (input, type) => {
    if (!input) return { valid: false, message: 'Input is required' };
    
    const sanitized = securityUtils.sanitizeInput(input.toString().trim());
    
    switch (type) {
      case 'email':
        return {
          valid: validationUtils.isValidEmail(sanitized),
          value: sanitized.toLowerCase(),
          message: validationUtils.isValidEmail(sanitized) ? null : 'Invalid email format'
        };
      case 'username':
        return {
          valid: validationUtils.isValidUsername(sanitized),
          value: sanitized,
          message: validationUtils.isValidUsername(sanitized) ? null : 'Username must be 3-50 characters, letters, numbers, and underscores only'
        };
      case 'phone':
        return {
          valid: validationUtils.isValidPhoneNumber(sanitized),
          value: sanitized,
          message: validationUtils.isValidPhoneNumber(sanitized) ? null : 'Invalid phone number format'
        };
      default:
        return {
          valid: true,
          value: sanitized,
          message: null
        };
    }
  }
};

// Audit utilities
const auditUtils = {
  // Create audit trail entry
  createAuditEntry: (eventType, userId, action, details = {}) => {
    return {
      eventType,
      userId,
      action,
      timestamp: new Date(),
      ipAddress: details.ipAddress || 'unknown',
      userAgent: details.userAgent || 'unknown',
      sessionId: details.sessionId,
      metadata: details.metadata || {},
      success: details.success !== false,
      riskLevel: details.riskLevel || 'low'
    };
  },

  // Format audit log for display
  formatAuditLog: (auditLog) => {
    return {
      id: auditLog._id,
      eventType: auditLog.eventType,
      action: auditLog.action,
      timestamp: auditLog.timestamp.toISOString(),
      user: auditLog.username || 'System',
      ipAddress: auditLog.ipAddress,
      success: auditLog.success,
      riskLevel: auditLog.riskLevel
    };
  }
};

module.exports = {
  passwordUtils,
  encryptionUtils,
  securityUtils,
  validationUtils,
  auditUtils
};
