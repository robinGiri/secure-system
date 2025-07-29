const AuditLog = require('../models/AuditLog');
const { logSecurityIncident } = require('../middleware/auditLogger');

/**
 * Detect suspicious login patterns and trigger appropriate security measures
 * @param {Object} req - Request object
 * @param {Object} user - User object
 * @returns {Object} Security assessment with risk level and recommended actions
 */
async function detectSuspiciousActivity(req, user) {
  const results = {
    riskLevel: 'low',
    requireAdditionalVerification: false,
    requireCaptcha: false,
    anomalies: []
  };

  // Check for unusual login location
  const userLastLogins = await AuditLog.find({
    userId: user._id,
    eventType: 'user_login',
    success: true
  }).sort({ timestamp: -1 }).limit(10);

  const ipAddress = req.ip;
  const userAgent = req.get('User-Agent');
  
  // If this is the first login, it's not suspicious but mark as new device
  if (userLastLogins.length === 0) {
    results.isNewDevice = true;
    return results;
  }
  
  // Check if this IP has been used by this user before
  const knownIP = userLastLogins.some(log => log.ipAddress === ipAddress);
  if (!knownIP) {
    results.isNewLocation = true;
    results.anomalies.push('new_ip_address');
    results.riskLevel = 'medium';
    results.requireAdditionalVerification = true;
  }
  
  // Check if user agent is different from previous logins
  const knownUserAgent = userLastLogins.some(log => log.userAgent === userAgent);
  if (!knownUserAgent) {
    results.isNewDevice = true;
    results.anomalies.push('new_device');
    results.riskLevel = 'medium';
  }
  
  // Check for rapid location change (impossible travel)
  // This would require geolocation lookup in production
  // For demo purposes, we'll just check if the IP is completely different
  if (userLastLogins.length > 0 && 
      ipAddress !== userLastLogins[0].ipAddress && 
      Date.now() - new Date(userLastLogins[0].timestamp).getTime() < 30 * 60 * 1000) {
    // If location changed drastically in less than 30 minutes
    results.impossibleTravel = true;
    results.anomalies.push('impossible_travel');
    results.riskLevel = 'high';
    results.requireAdditionalVerification = true;
    results.requireCaptcha = true;
    
    // Log security incident
    await logSecurityIncident(
      req, 
      'impossible_travel', 
      `User ${user.username} logged in from different IP in short timeframe`, 
      'medium'
    );
  }
  
  // Check for too many recent failed attempts
  const recentFailedAttempts = await AuditLog.countDocuments({
    userId: user._id,
    eventType: 'login_failed',
    createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
  });
  
  if (recentFailedAttempts >= 3) {
    results.anomalies.push('multiple_failed_attempts');
    results.recentFailedAttempts = recentFailedAttempts;
    results.riskLevel = Math.max(results.riskLevel === 'high' ? 2 : results.riskLevel === 'medium' ? 1 : 0, 1);
    results.requireCaptcha = true;
  }
  
  // Check for off-hours access (would be implemented with user timezone preferences)
  const hour = new Date().getHours();
  if (hour >= 0 && hour <= 5) {
    results.offHoursAccess = true;
    results.anomalies.push('off_hours_access');
  }
  
  return results;
}

/**
 * Create and apply progressive security measures based on risk assessment
 * @param {Object} req - Request object
 * @param {Object} user - User object
 * @param {Object} suspiciousActivity - Results from detectSuspiciousActivity
 */
async function applySecurityMeasures(req, user, suspiciousActivity) {
  // Set appropriate session flags
  if (suspiciousActivity.requireCaptcha) {
    req.session.requireCaptcha = true;
  }
  
  if (suspiciousActivity.requireAdditionalVerification) {
    req.session.requireEmailVerification = true;
    
    // In production, send verification email
    // For demo, we just set the session flag
  }
  
  // For high-risk activity, reduce session duration
  if (suspiciousActivity.riskLevel === 'high') {
    req.session.cookie.maxAge = 15 * 60 * 1000; // 15 minutes
  }
  
  // For new devices/locations, enforce MFA if available
  if ((suspiciousActivity.isNewLocation || suspiciousActivity.isNewDevice) && user.mfaEnabled) {
    req.session.requireMfaVerification = true;
  }
}

module.exports = {
  detectSuspiciousActivity,
  applySecurityMeasures
};
