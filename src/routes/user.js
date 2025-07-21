const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { 
  authenticateSession, 
  authorize, 
  requireOwnership,
  sensitiveOperationLimiter 
} = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityEvent } = require('../middleware/auth');
const { logDataAccess } = require('../middleware/auditLogger');

const router = express.Router();

// Get specific user profile (for admins or user accessing their own)
router.get('/profile/:userId', authenticateSession, asyncHandler(async (req, res) => {
  const userId = req.params.userId;
  
  // Check if user can access this profile
  if (req.user.role !== 'admin' && req.user._id.toString() !== userId.toString()) {
    await logSecurityEvent(req, 'authorization_failed', 'Attempted to access another user profile', req.user._id, false);
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  const user = await User.findById(userId).select('-password -mfaSecret -passwordHistory');
  
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  await logDataAccess('user_profile', userId, 'view', req);

  res.json({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        address: user.address,
        profilePicture: user.profilePicture,
        role: user.role,
        accountNumber: user.accountNumber,
        accountType: user.accountType,
        balance: user.balance,
        mfaEnabled: user.mfaEnabled,
        isVerified: user.isVerified,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    }
  });
}));

// Get current user's profile
router.get('/profile', authenticateSession, asyncHandler(async (req, res) => {
  const userId = req.user._id;

  const user = await User.findById(userId).select('-password -mfaSecret -passwordHistory');
  
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  await logDataAccess('user_profile', userId, 'view', req);

  res.json({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        address: user.address,
        profilePicture: user.profilePicture,
        role: user.role,
        accountNumber: user.accountNumber,
        accountType: user.accountType,
        balance: user.balance,
        mfaEnabled: user.mfaEnabled,
        isVerified: user.isVerified,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    }
  });
}));

// Update user profile
router.put('/profile', authenticateSession, sensitiveOperationLimiter, [
  body('firstName').optional().isLength({ min: 1, max: 50 }).trim(),
  body('lastName').optional().isLength({ min: 1, max: 50 }).trim(),
  body('phoneNumber').optional().matches(/^\+?[\d\s\-\(\)]+$/),
  body('address.street').optional().isLength({ max: 100 }),
  body('address.city').optional().isLength({ max: 50 }),
  body('address.state').optional().isLength({ max: 50 }),
  body('address.postalCode').optional().isLength({ max: 20 }),
  body('address.country').optional().isLength({ max: 50 })
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const user = req.user;
  const allowedUpdates = ['firstName', 'lastName', 'phoneNumber', 'address'];
  const updates = {};

  // Filter allowed updates
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  // Store old values for audit
  const oldValues = {};
  Object.keys(updates).forEach(key => {
    oldValues[key] = user[key];
  });

  // Update user
  Object.assign(user, updates);
  await user.save();

  // Log the profile update
  const auditLog = new AuditLog({
    eventType: 'profile_updated',
    userId: user._id,
    username: user.username,
    userRole: user.role,
    sessionId: req.sessionID,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    action: 'Updated profile information',
    resource: 'user_profile',
    resourceId: user._id.toString(),
    oldValues,
    newValues: updates,
    success: true
  });

  await auditLog.save();

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        address: user.address
      }
    }
  });
}));

// Get user's active sessions
router.get('/sessions', authenticateSession, asyncHandler(async (req, res) => {
  const user = req.user;
  
  const sessions = user.activeSessions.map(session => ({
    sessionId: session.sessionId,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    createdAt: session.createdAt,
    lastActivity: session.lastActivity,
    isCurrent: session.sessionId === req.sessionID
  }));

  res.json({
    success: true,
    data: {
      sessions
    }
  });
}));

// Terminate a session
router.delete('/sessions/:sessionId', authenticateSession, asyncHandler(async (req, res) => {
  const { sessionId } = req.params;
  const user = req.user;

  // Check if session belongs to user
  const session = user.activeSessions.find(s => s.sessionId === sessionId);
  if (!session) {
    return res.status(404).json({
      success: false,
      message: 'Session not found'
    });
  }

  // Remove session
  await user.removeSession(sessionId);

  await logSecurityEvent(req, 'session_destroyed', `Session ${sessionId} terminated`, user._id, true);

  res.json({
    success: true,
    message: 'Session terminated successfully'
  });
}));

// Get user's activity log
router.get('/activity', authenticateSession, asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, eventType, startDate, endDate } = req.query;
  const userId = req.user._id;

  const filter = { userId };
  
  if (eventType) {
    filter.eventType = eventType;
  }
  
  if (startDate || endDate) {
    filter.timestamp = {};
    if (startDate) filter.timestamp.$gte = new Date(startDate);
    if (endDate) filter.timestamp.$lte = new Date(endDate);
  }

  const skip = (parseInt(page) - 1) * parseInt(limit);

  const activities = await AuditLog.find(filter)
    .sort({ timestamp: -1 })
    .skip(skip)
    .limit(parseInt(limit))
    .select('eventType action timestamp ipAddress userAgent success');

  const total = await AuditLog.countDocuments(filter);

  res.json({
    success: true,
    data: {
      activities,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    }
  });
}));

// Get user's security settings
router.get('/security', authenticateSession, asyncHandler(async (req, res) => {
  const user = req.user;
  
  res.json({
    success: true,
    data: {
      mfaEnabled: user.mfaEnabled,
      activeSessions: user.activeSessions.length,
      lastLogin: user.lastLogin,
      lastPasswordChange: user.lastPasswordChange,
      passwordExpiresAt: user.passwordExpiresAt,
      isLocked: user.isLocked,
      loginAttempts: user.loginAttempts
    }
  });
}));

// Update account type (for eligible users)
router.put('/account-type', authenticateSession, [
  body('accountType').isIn(['savings', 'checking', 'business']).withMessage('Invalid account type')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { accountType } = req.body;
  const user = req.user;

  const oldAccountType = user.accountType;
  user.accountType = accountType;
  await user.save();

  // Log the account type change
  const auditLog = new AuditLog({
    eventType: 'profile_updated',
    userId: user._id,
    username: user.username,
    userRole: user.role,
    sessionId: req.sessionID,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    action: `Changed account type from ${oldAccountType} to ${accountType}`,
    resource: 'account_type',
    resourceId: user._id.toString(),
    oldValues: { accountType: oldAccountType },
    newValues: { accountType },
    success: true
  });

  await auditLog.save();

  res.json({
    success: true,
    message: 'Account type updated successfully',
    data: {
      accountType: user.accountType
    }
  });
}));

// Deactivate account
router.post('/deactivate', authenticateSession, sensitiveOperationLimiter, [
  body('password').notEmpty().withMessage('Password is required for account deactivation'),
  body('reason').optional().isLength({ max: 500 }).withMessage('Reason must be less than 500 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { password, reason } = req.body;
  const user = req.user;

  // Verify password
  if (!(await user.comparePassword(password))) {
    await logSecurityEvent(req, 'account_deactivation', 'Account deactivation failed - invalid password', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });
  }

  // Check if user has pending transactions or non-zero balance
  if (user.balance > 0) {
    return res.status(400).json({
      success: false,
      message: 'Cannot deactivate account with remaining balance. Please transfer or withdraw all funds first.'
    });
  }

  // Deactivate account
  user.isActive = false;
  await user.save();

  // Log the deactivation
  const auditLog = new AuditLog({
    eventType: 'account_deactivated',
    userId: user._id,
    username: user.username,
    userRole: user.role,
    sessionId: req.sessionID,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    action: 'Account deactivated',
    resource: 'user_account',
    resourceId: user._id.toString(),
    metadata: { reason },
    success: true
  });

  await auditLog.save();

  // Destroy session
  req.session.destroy();

  res.json({
    success: true,
    message: 'Account deactivated successfully'
  });
}));

module.exports = router;
