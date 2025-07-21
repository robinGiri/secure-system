const AuditLog = require('../models/AuditLog');
const winston = require('winston');
const crypto = require('crypto');

// Configure Winston logger for audit logs
const auditLogger = winston.createLogger({
  level: process.env.AUDIT_LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'security-audit' },
  transports: [
    new winston.transports.File({ 
      filename: process.env.AUDIT_LOG_FILE || 'logs/audit.log',
      maxsize: 10485760, // 10MB
      maxFiles: 10,
      tailable: true
    }),
    new winston.transports.File({ 
      filename: 'logs/security-events.log', 
      level: 'warn',
      maxsize: 10485760,
      maxFiles: 5,
      tailable: true
    })
  ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
  auditLogger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Main audit logging middleware
const auditLoggerMiddleware = async (req, res, next) => {
  const startTime = Date.now();
  const requestId = generateRequestId();
  
  // Store request info for later use
  req.audit = {
    requestId,
    startTime,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    method: req.method,
    url: req.originalUrl,
    endpoint: req.route?.path || req.originalUrl
  };

  // Override res.json to capture response data
  const originalJson = res.json;
  let responseBody;
  
  res.json = function(body) {
    responseBody = body;
    return originalJson.call(this, body);
  };

  // Log request
  await logRequest(req);

  // Listen for response finish
  res.on('finish', async () => {
    const duration = Date.now() - startTime;
    await logResponse(req, res, responseBody, duration);
  });

  next();
};

// Log incoming requests
const logRequest = async (req) => {
  try {
    const sensitiveFields = ['password', 'confirmPassword', 'currentPassword', 'newPassword', 'mfaToken', 'token'];
    const sanitizedBody = sanitizeData(req.body, sensitiveFields);
    
    const logData = {
      requestId: req.audit.requestId,
      type: 'request',
      method: req.method,
      url: req.originalUrl,
      ipAddress: req.audit.ipAddress,
      userAgent: req.audit.userAgent,
      userId: req.user?._id,
      username: req.user?.username,
      sessionId: req.sessionID,
      body: sanitizedBody,
      query: req.query,
      params: req.params,
      headers: sanitizeHeaders(req.headers),
      timestamp: new Date()
    };

    auditLogger.info('HTTP Request', logData);
  } catch (error) {
    console.error('Error logging request:', error);
  }
};

// Log responses
const logResponse = async (req, res, responseBody, duration) => {
  try {
    const eventType = determineEventType(req, res);
    const riskLevel = assessRiskLevel(req, res);
    const success = res.statusCode < 400;

    // Create audit log entry
    const auditLogEntry = new AuditLog({
      eventType,
      userId: req.user?._id,
      username: req.user?.username || extractUsernameFromRequest(req),
      userRole: req.user?.role,
      sessionId: req.sessionID,
      ipAddress: req.audit.ipAddress,
      userAgent: req.audit.userAgent,
      method: req.method,
      url: req.originalUrl,
      endpoint: req.audit.endpoint,
      requestId: req.audit.requestId,
      action: generateActionDescription(req, res),
      resource: extractResourceFromPath(req.originalUrl),
      success,
      statusCode: res.statusCode,
      riskLevel,
      duration,
      metadata: {
        responseSize: JSON.stringify(responseBody || {}).length,
        query: req.query,
        params: req.params
      }
    });

    // Add security flags if needed
    const securityFlags = detectSecurityFlags(req, res, responseBody);
    if (securityFlags.length > 0) {
      auditLogEntry.securityFlags = securityFlags;
      auditLogEntry.riskLevel = 'high';
    }

    // Save to database
    await auditLogEntry.save();

    // Log to file
    const logData = {
      requestId: req.audit.requestId,
      type: 'response',
      eventType,
      userId: req.user?._id,
      username: req.user?.username,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      success,
      riskLevel,
      ipAddress: req.audit.ipAddress,
      timestamp: new Date()
    };

    if (success) {
      auditLogger.info('HTTP Response', logData);
    } else {
      auditLogger.warn('HTTP Error Response', {
        ...logData,
        error: responseBody?.message || 'Unknown error'
      });
    }

    // Log security events separately
    if (riskLevel === 'high' || riskLevel === 'critical') {
      auditLogger.warn('Security Event', {
        ...logData,
        securityFlags,
        alert: true
      });
    }

  } catch (error) {
    console.error('Error logging response:', error);
  }
};

// Utility functions
const generateRequestId = () => {
  return crypto.randomBytes(16).toString('hex');
};

const getClientIP = (req) => {
  return req.ip || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         'unknown';
};

const sanitizeData = (data, sensitiveFields) => {
  if (!data || typeof data !== 'object') return data;
  
  const sanitized = { ...data };
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  return sanitized;
};

const sanitizeHeaders = (headers) => {
  const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];
  const sanitized = { ...headers };
  
  sensitiveHeaders.forEach(header => {
    if (sanitized[header]) {
      sanitized[header] = '[REDACTED]';
    }
  });
  
  return sanitized;
};

const determineEventType = (req, res) => {
  const { method, originalUrl } = req;
  const statusCode = res.statusCode;

  // Authentication events
  if (originalUrl.includes('/auth/login')) {
    return statusCode < 400 ? 'user_login' : 'login_failed';
  }
  if (originalUrl.includes('/auth/logout')) return 'user_logout';
  if (originalUrl.includes('/auth/register')) return 'user_registration';
  if (originalUrl.includes('/auth/password')) return 'password_change';
  if (originalUrl.includes('/auth/mfa')) return 'mfa_verification';

  // Transaction events
  if (originalUrl.includes('/transactions')) {
    if (method === 'POST') return 'transaction_created';
    if (method === 'PUT' || method === 'PATCH') return 'transaction_updated';
    if (method === 'DELETE') return 'transaction_deleted';
    return 'transaction_access';
  }

  // Profile events
  if (originalUrl.includes('/profile') || originalUrl.includes('/user')) {
    if (method === 'PUT' || method === 'PATCH') return 'profile_updated';
    return 'profile_access';
  }

  // Admin events
  if (originalUrl.includes('/admin')) return 'admin_action';

  // Data access
  if (method === 'GET') return 'data_access';
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') return 'data_modification';
  if (method === 'DELETE') return 'data_deletion';

  return 'general_activity';
};

const assessRiskLevel = (req, res) => {
  let riskScore = 0;

  // Failed authentication
  if (res.statusCode === 401 || res.statusCode === 403) {
    riskScore += 30;
  }

  // High-value transactions
  if (req.originalUrl.includes('/transactions') && req.body?.amount > 10000) {
    riskScore += 40;
  }

  // Admin operations
  if (req.originalUrl.includes('/admin')) {
    riskScore += 20;
  }

  // Off-hours activity
  const hour = new Date().getHours();
  if (hour < 6 || hour > 22) {
    riskScore += 10;
  }

  // Multiple failed attempts from same IP
  if (res.statusCode >= 400 && req.audit?.failedAttempts > 3) {
    riskScore += 30;
  }

  // Password operations
  if (req.originalUrl.includes('password') || req.originalUrl.includes('mfa')) {
    riskScore += 15;
  }

  if (riskScore >= 70) return 'critical';
  if (riskScore >= 40) return 'high';
  if (riskScore >= 20) return 'medium';
  return 'low';
};

const detectSecurityFlags = (req, res, responseBody) => {
  const flags = [];

  // Multiple failed login attempts
  if (req.originalUrl.includes('/auth/login') && res.statusCode === 401) {
    flags.push({
      flag: 'failed_login',
      reason: 'Failed login attempt detected'
    });
  }

  // Potential SQL injection patterns
  const sqlPatterns = /(\b(union|select|insert|update|delete|drop|create|alter)\b|--|\/\*|\*\/|;)/i;
  const queryString = JSON.stringify(req.query) + JSON.stringify(req.body);
  if (sqlPatterns.test(queryString)) {
    flags.push({
      flag: 'sql_injection_attempt',
      reason: 'Potential SQL injection pattern detected'
    });
  }

  // XSS patterns
  const xssPatterns = /<script|javascript:|onload=|onerror=|eval\(|document\.|window\./i;
  if (xssPatterns.test(queryString)) {
    flags.push({
      flag: 'xss_attempt',
      reason: 'Potential XSS pattern detected'
    });
  }

  // Large file uploads
  if (req.headers['content-length'] && parseInt(req.headers['content-length']) > 10485760) {
    flags.push({
      flag: 'large_upload',
      reason: 'Large file upload detected'
    });
  }

  // Suspicious user agents
  const suspiciousAgents = /bot|crawler|spider|scraper|curl|wget|postman/i;
  if (suspiciousAgents.test(req.audit.userAgent)) {
    flags.push({
      flag: 'suspicious_user_agent',
      reason: 'Potentially automated request detected'
    });
  }

  return flags;
};

const generateActionDescription = (req, res) => {
  const { method, originalUrl } = req;
  const statusCode = res.statusCode;

  if (originalUrl.includes('/auth/login')) {
    return statusCode < 400 ? 'User logged in successfully' : 'Login attempt failed';
  }
  if (originalUrl.includes('/auth/logout')) return 'User logged out';
  if (originalUrl.includes('/transactions')) {
    if (method === 'POST') return 'Created new transaction';
    if (method === 'GET') return 'Viewed transactions';
    if (method === 'PUT') return 'Updated transaction';
    if (method === 'DELETE') return 'Deleted transaction';
  }

  return `${method} request to ${originalUrl}`;
};

const extractResourceFromPath = (path) => {
  const segments = path.split('/').filter(segment => segment);
  if (segments.length === 0) return 'root';
  
  // Remove API prefix
  if (segments[0] === 'api') segments.shift();
  
  return segments[0] || 'unknown';
};

const extractUsernameFromRequest = (req) => {
  return req.body?.username || req.body?.email || req.query?.username || 'anonymous';
};

// Specialized logging functions
const logSecurityIncident = async (eventType, description, req, severity = 'medium') => {
  try {
    const auditLog = new AuditLog({
      eventType: 'security_violation',
      userId: req.user?._id,
      username: req.user?.username,
      userRole: req.user?.role,
      sessionId: req.sessionID,
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent'),
      method: req.method,
      url: req.originalUrl,
      action: description,
      success: false,
      riskLevel: severity,
      securityFlags: [{
        flag: eventType,
        reason: description
      }],
      metadata: {
        incidentType: eventType,
        severity,
        timestamp: new Date()
      }
    });

    await auditLog.save();

    auditLogger.error('Security Incident', {
      eventType,
      description,
      severity,
      userId: req.user?._id,
      ipAddress: getClientIP(req),
      url: req.originalUrl,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('Failed to log security incident:', error);
  }
};

const logDataAccess = async (resourceType, resourceId, action, req) => {
  try {
    const auditLog = new AuditLog({
      eventType: 'data_access',
      userId: req.user?._id,
      username: req.user?.username,
      userRole: req.user?.role,
      sessionId: req.sessionID,
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent'),
      action: `${action} ${resourceType}`,
      resource: resourceType,
      resourceId: resourceId?.toString(),
      success: true,
      riskLevel: resourceType === 'user' || resourceType === 'transaction' ? 'medium' : 'low'
    });

    await auditLog.save();
  } catch (error) {
    console.error('Failed to log data access:', error);
  }
};

module.exports = {
  auditLoggerMiddleware,
  logSecurityIncident,
  logDataAccess,
  auditLogger
};
