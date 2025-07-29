const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const rateLimit = require('express-rate-limit');

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      await logSecurityEvent(req, 'authentication_failed', 'No token provided', null, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Access denied. No token provided.' 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password -mfaSecret');
    
    if (!user) {
      await logSecurityEvent(req, 'authentication_failed', 'Invalid token - user not found', null, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token.' 
      });
    }

    if (!user.isActive) {
      await logSecurityEvent(req, 'authentication_failed', 'Account is deactivated', user._id, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Account is deactivated.' 
      });
    }

    if (user.isLocked) {
      await logSecurityEvent(req, 'authentication_failed', 'Account is locked', user._id, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Account is locked due to multiple failed login attempts.' 
      });
    }

    // Check if password is expired
    if (user.isPasswordExpired()) {
      return res.status(401).json({ 
        success: false, 
        message: 'Password has expired. Please reset your password.',
        requirePasswordReset: true
      });
    }

    req.user = user;
    next();
  } catch (error) {
    await logSecurityEvent(req, 'authentication_failed', `Token verification failed: ${error.message}`, null, false);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Token has expired.' 
      });
    }
    
    return res.status(403).json({ 
      success: false, 
      message: 'Invalid token.' 
    });
  }
};

// Session-based Authentication Middleware
const authenticateSession = async (req, res, next) => {
  try {
    if (!req.session || !req.session.user) {
      await logSecurityEvent(req, 'authentication_failed', 'No valid session', null, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Please log in to access this resource.' 
      });
    }

    const user = await User.findById(req.session.user.id).select('-password -mfaSecret');
    
    if (!user) {
      req.session.destroy();
      await logSecurityEvent(req, 'authentication_failed', 'Session user not found', null, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid session. Please log in again.' 
      });
    }

    if (!user.isActive) {
      req.session.destroy();
      await logSecurityEvent(req, 'authentication_failed', 'Account is deactivated', user._id, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Account is deactivated.' 
      });
    }

    if (user.isLocked) {
      req.session.destroy();
      await logSecurityEvent(req, 'authentication_failed', 'Account is locked', user._id, false);
      return res.status(401).json({ 
        success: false, 
        message: 'Account is locked.' 
      });
    }

    // Update last activity
    req.session.lastActivity = new Date();
    req.user = user;
    next();
  } catch (error) {
    await logSecurityEvent(req, 'authentication_failed', `Session verification failed: ${error.message}`, null, false);
    return res.status(500).json({ 
      success: false, 
      message: 'Authentication error.' 
    });
  }
};

// Role-based Authorization Middleware
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication required.' 
      });
    }

    if (!roles.includes(req.user.role)) {
      logSecurityEvent(req, 'authorization_failed', `Insufficient privileges. Required: ${roles.join(', ')}, Has: ${req.user.role}`, req.user._id, false);
      return res.status(403).json({ 
        success: false, 
        message: 'Insufficient privileges.' 
      });
    }

    next();
  };
};

// Permission-based Authorization Middleware
const checkPermission = (resource, action) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication required.' 
      });
    }

    if (!req.user.hasPermission(resource, action)) {
      await logSecurityEvent(
        req, 
        'authorization_failed', 
        `Permission denied for ${action} on ${resource}`, 
        req.user._id, 
        false
      );
      return res.status(403).json({ 
        success: false, 
        message: `Permission denied for ${action} on ${resource}.` 
      });
    }

    next();
  };
};

// Account Ownership Middleware
const requireOwnership = (userIdParam = 'userId') => {
  return async (req, res, next) => {
    const resourceUserId = req.params[userIdParam] || req.body[userIdParam];
    
    if (!resourceUserId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID parameter is required.' 
      });
    }

    // Admins can access any resource
    if (req.user.role === 'admin') {
      return next();
    }

    // Users can only access their own resources
    if (req.user._id.toString() !== resourceUserId.toString()) {
      await logSecurityEvent(
        req, 
        'authorization_failed', 
        `Attempted to access another user's resource`, 
        req.user._id, 
        false
      );
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied. You can only access your own resources.' 
      });
    }

    next();
  };
};

// MFA Requirement Middleware
const requireMFA = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication required.' 
      });
    }

    // Check if MFA is enabled for the user
    if (!req.user.mfaEnabled) {
      return res.status(403).json({ 
        success: false, 
        message: 'Multi-factor authentication is required for this action.',
        requireMFA: true
      });
    }

    // Check if MFA has been verified in this session
    if (!req.session.mfaVerified) {
      return res.status(403).json({ 
        success: false, 
        message: 'Please verify your multi-factor authentication.',
        requireMFAVerification: true
      });
    }

    next();
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      message: 'MFA verification error.' 
    });
  }
};

// Rate Limiting for Sensitive Operations
const sensitiveOperationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many sensitive operations from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    await logSecurityEvent(
      req, 
      'rate_limit_exceeded', 
      'Sensitive operation rate limit exceeded', 
      req.user?._id, 
      false
    );
    res.status(429).json({
      success: false,
      message: 'Too many sensitive operations. Please try again later.'
    });
  }
});

// Progressive Login Rate Limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 login requests per windowMs
  skipSuccessfulRequests: true,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: 'Too many login attempts from this IP, please try again later.',
  handler: async (req, res) => {
    const username = req.body.username || 'unknown';
    
    await logSecurityEvent(
      req, 
      'rate_limit_exceeded', 
      `Login rate limit exceeded for ${username}`, 
      null, 
      false
    );
    
    // Log security incident if extreme number of attempts
    const ipLoginAttempts = await AuditLog.countDocuments({
      ipAddress: req.ip, 
      eventType: 'login_failed',
      createdAt: { $gt: new Date(Date.now() - 60 * 60 * 1000) } // Last hour
    });
    
    if (ipLoginAttempts > 20) {
      await logSecurityIncident(
        req,
        'brute_force_attempt',
        `Possible brute force attack from IP ${req.ip}`,
        'high'
      );
    }
    
    res.status(429).json({
      success: false,
      message: 'Too many login attempts. Please try again later.',
      retryAfter: Math.ceil(15 * 60 / 60), // Minutes until retry allowed
      requireCaptcha: true
    });
  }
});

// IP Whitelist Middleware (for admin operations)
const ipWhitelist = (allowedIPs = []) => {
  return async (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    
    if (allowedIPs.length > 0 && !allowedIPs.includes(clientIP)) {
      await logSecurityEvent(
        req, 
        'security_violation', 
        `Unauthorized IP address attempted admin access: ${clientIP}`, 
        req.user?._id, 
        false
      );
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied from this IP address.' 
      });
    }

    next();
  };
};

// Utility function to log security events
const logSecurityEvent = async (req, eventType, action, userId = null, success = true) => {
  try {
    const auditLog = new AuditLog({
      eventType,
      userId: userId || req.user?._id,
      username: req.user?.username || req.body?.username,
      userRole: req.user?.role,
      sessionId: req.sessionID,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      method: req.method,
      url: req.originalUrl,
      action,
      success,
      timestamp: new Date()
    });

    await auditLog.save();
  } catch (error) {
    // Failed to log security event
    // In production, this should use a proper logging mechanism
  }
};

module.exports = {
  authenticateToken,
  authenticateSession,
  authorize,
  checkPermission,
  requireOwnership,
  requireMFA,
  sensitiveOperationLimiter,
  loginLimiter,
  ipWhitelist,
  logSecurityEvent
};
