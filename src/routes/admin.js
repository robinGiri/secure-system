const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');
const { 
  authenticateSession, 
  requireRole,
  requirePermission,
  addUserPermissions,
  sensitiveOperationLimiter,
  ipWhitelist 
} = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityEvent } = require('../middleware/auth');

const router = express.Router();

// All admin routes require authentication and admin role
router.use(authenticateSession);
router.use(requireRole('admin'));
router.use(addUserPermissions);

// Admin dashboard - system overview
router.get('/dashboard', asyncHandler(async (req, res) => {
  const { period = '24' } = req.query; // hours
  const since = new Date(Date.now() - parseInt(period) * 60 * 60 * 1000);

  // Get system statistics
  const [
    totalUsers,
    activeUsers,
    totalTransactions,
    recentTransactions,
    securityEvents,
    systemHealth
  ] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ lastLogin: { $gte: since } }),
    Transaction.countDocuments(),
    Transaction.countDocuments({ createdAt: { $gte: since } }),
    AuditLog.getSecurityEvents(parseInt(period)),
    AuditLog.getSystemHealth(parseInt(period) / 24) // Convert to days
  ]);

  // Get high-risk transactions
  const highRiskTransactions = await Transaction.find({
    riskScore: { $gte: 70 },
    createdAt: { $gte: since }
  }).populate('fromAccount', 'username accountNumber');

  // Get failed login attempts by IP
  const failedLogins = await AuditLog.getFailedLogins(parseInt(period));

  // Get suspicious activities
  const suspiciousActivities = await AuditLog.getSuspiciousActivity(parseInt(period));

  await logSecurityEvent(req, 'admin_action', 'Accessed admin dashboard', req.user._id, true);

  res.json({
    success: true,
    data: {
      overview: {
        totalUsers,
        activeUsers,
        totalTransactions,
        recentTransactions,
        securityEventsCount: securityEvents.length
      },
      systemHealth: systemHealth[0] || {},
      securityEvents,
      highRiskTransactions,
      failedLogins,
      suspiciousActivities,
      period: `${period} hours`
    }
  });
}));

// Get all users with pagination and filtering
router.get('/users', requirePermission('users', 'read'), asyncHandler(async (req, res) => {
  const { 
    page = 1, 
    limit = 20, 
    role, 
    isActive, 
    search,
    sortBy = 'createdAt',
    sortOrder = 'desc'
  } = req.query;

  const filter = {};
  if (role) filter.role = role;
  if (isActive !== undefined) filter.isActive = isActive === 'true';
  if (search) {
    filter.$or = [
      { username: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
      { firstName: { $regex: search, $options: 'i' } },
      { lastName: { $regex: search, $options: 'i' } },
      { accountNumber: { $regex: search, $options: 'i' } }
    ];
  }

  const skip = (parseInt(page) - 1) * parseInt(limit);
  const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

  const users = await User.find(filter)
    .select('-password -mfaSecret -passwordHistory')
    .sort(sort)
    .skip(skip)
    .limit(parseInt(limit));

  const total = await User.countDocuments(filter);

  await logSecurityEvent(req, 'data_access', `Viewed users list (page ${page})`, req.user._id, true);

  res.json({
    success: true,
    data: {
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    }
  });
}));

// Get specific user details
router.get('/users/:userId', requirePermission('users', 'read'), asyncHandler(async (req, res) => {
  const { userId } = req.params;

  const user = await User.findById(userId).select('-password -mfaSecret -passwordHistory');
  
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Get user's recent transactions
  const recentTransactions = await Transaction.find({
    $or: [{ fromAccount: userId }, { toAccount: userId }]
  })
  .populate('fromAccount', 'username accountNumber')
  .populate('toAccount', 'username accountNumber')
  .sort({ createdAt: -1 })
  .limit(10);

  // Get user's recent activities
  const recentActivities = await AuditLog.find({ userId })
    .sort({ timestamp: -1 })
    .limit(20);

  await logSecurityEvent(req, 'data_access', `Viewed user details for ${user.username}`, req.user._id, true);

  res.json({
    success: true,
    data: {
      user,
      recentTransactions,
      recentActivities
    }
  });
}));

// Update user (admin only)
router.put('/users/:userId', requirePermission('users', 'update'), sensitiveOperationLimiter, [
  body('role').optional().isIn(['user', 'admin', 'manager', 'viewer']),
  body('isActive').optional().isBoolean(),
  body('balance').optional().isFloat({ min: 0 })
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { userId } = req.params;
  const allowedUpdates = ['role', 'isActive', 'balance'];
  const updates = {};

  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Store old values for audit
  const oldValues = {};
  Object.keys(updates).forEach(key => {
    oldValues[key] = user[key];
  });

  // Update user
  Object.assign(user, updates);
  await user.save();

  // Log the admin action
  const auditLog = new AuditLog({
    eventType: 'admin_action',
    userId: req.user._id,
    username: req.user.username,
    userRole: req.user.role,
    sessionId: req.sessionID,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    action: `Updated user ${user.username}`,
    resource: 'user',
    resourceId: userId,
    oldValues,
    newValues: updates,
    success: true,
    riskLevel: 'high'
  });

  await auditLog.save();

  res.json({
    success: true,
    message: 'User updated successfully',
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        balance: user.balance
      }
    }
  });
}));

// Lock/unlock user account
router.patch('/users/:userId/lock', sensitiveOperationLimiter, [
  body('action').isIn(['lock', 'unlock']).withMessage('Action must be lock or unlock'),
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

  const { userId } = req.params;
  const { action, reason } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  if (action === 'lock') {
    user.lockUntil = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    user.loginAttempts = 5; // Max attempts
  } else {
    user.lockUntil = undefined;
    user.loginAttempts = 0;
  }

  await user.save();

  // Log the admin action
  const auditLog = new AuditLog({
    eventType: action === 'lock' ? 'account_locked' : 'account_unlocked',
    userId: req.user._id,
    username: req.user.username,
    userRole: req.user.role,
    sessionId: req.sessionID,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    action: `${action}ed user account: ${user.username}`,
    resource: 'user_account',
    resourceId: userId,
    metadata: { reason, targetUser: user.username },
    success: true,
    riskLevel: 'high'
  });

  await auditLog.save();

  res.json({
    success: true,
    message: `User account ${action}ed successfully`,
    data: {
      userId,
      action,
      isLocked: user.isLocked
    }
  });
}));

// Get all transactions with admin privileges
router.get('/transactions', asyncHandler(async (req, res) => {
  const { 
    page = 1, 
    limit = 20, 
    status, 
    type,
    minAmount,
    maxAmount,
    riskScore,
    startDate,
    endDate 
  } = req.query;

  const filter = {};
  if (status) filter.status = status;
  if (type) filter.type = type;
  if (minAmount || maxAmount) {
    filter.amount = {};
    if (minAmount) filter.amount.$gte = parseFloat(minAmount);
    if (maxAmount) filter.amount.$lte = parseFloat(maxAmount);
  }
  if (riskScore) {
    filter.riskScore = { $gte: parseInt(riskScore) };
  }
  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }

  const skip = (parseInt(page) - 1) * parseInt(limit);

  const transactions = await Transaction.find(filter)
    .populate('fromAccount', 'username accountNumber firstName lastName')
    .populate('toAccount', 'username accountNumber firstName lastName')
    .populate('processedBy', 'username')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit));

  const total = await Transaction.countDocuments(filter);

  await logSecurityEvent(req, 'data_access', `Admin viewed transactions (page ${page})`, req.user._id, true);

  res.json({
    success: true,
    data: {
      transactions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    }
  });
}));

// Approve/reject pending transaction
router.patch('/transactions/:transactionId/review', sensitiveOperationLimiter, [
  body('action').isIn(['approve', 'reject']).withMessage('Action must be approve or reject'),
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

  const { transactionId } = req.params;
  const { action, reason } = req.body;

  const transaction = await Transaction.findOne({ transactionId });
  if (!transaction) {
    return res.status(404).json({
      success: false,
      message: 'Transaction not found'
    });
  }

  if (transaction.status !== 'pending') {
    return res.status(400).json({
      success: false,
      message: 'Transaction is not pending review'
    });
  }

  const oldStatus = transaction.status;
  
  if (action === 'approve') {
    transaction.status = 'completed';
    transaction.processedAt = new Date();
  } else {
    transaction.status = 'failed';
    
    // Reverse balance changes if needed
    if (['transfer', 'withdrawal', 'payment'].includes(transaction.type)) {
      const fromUser = await User.findById(transaction.fromAccount);
      if (fromUser) {
        fromUser.balance += transaction.amount;
        await fromUser.save();
      }
    }
  }

  transaction.processedBy = req.user._id;
  await transaction.save();

  // Log the admin action
  const auditLog = new AuditLog({
    eventType: 'transaction_updated',
    userId: req.user._id,
    username: req.user.username,
    userRole: req.user.role,
    sessionId: req.sessionID,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    action: `${action}ed transaction ${transactionId}`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    oldValues: { status: oldStatus },
    newValues: { status: transaction.status },
    metadata: { reason, action },
    success: true,
    riskLevel: 'high'
  });

  await auditLog.save();

  res.json({
    success: true,
    message: `Transaction ${action}ed successfully`,
    data: {
      transactionId,
      status: transaction.status,
      action
    }
  });
}));

// Get audit logs
router.get('/audit-logs', asyncHandler(async (req, res) => {
  const { 
    page = 1, 
    limit = 50, 
    eventType, 
    userId,
    riskLevel,
    success,
    startDate,
    endDate 
  } = req.query;

  const filter = {};
  if (eventType) filter.eventType = eventType;
  if (userId) filter.userId = userId;
  if (riskLevel) filter.riskLevel = riskLevel;
  if (success !== undefined) filter.success = success === 'true';
  if (startDate || endDate) {
    filter.timestamp = {};
    if (startDate) filter.timestamp.$gte = new Date(startDate);
    if (endDate) filter.timestamp.$lte = new Date(endDate);
  }

  const skip = (parseInt(page) - 1) * parseInt(limit);

  const auditLogs = await AuditLog.find(filter)
    .populate('userId', 'username email')
    .sort({ timestamp: -1 })
    .skip(skip)
    .limit(parseInt(limit));

  const total = await AuditLog.countDocuments(filter);

  await logSecurityEvent(req, 'data_access', `Admin viewed audit logs (page ${page})`, req.user._id, true);

  res.json({
    success: true,
    data: {
      auditLogs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    }
  });
}));

// Get security reports
router.get('/security/report', asyncHandler(async (req, res) => {
  const { period = '7' } = req.query; // days
  const since = new Date(Date.now() - parseInt(period) * 24 * 60 * 60 * 1000);

  const [
    securityEvents,
    failedLogins,
    suspiciousActivities,
    highRiskTransactions,
    accountLocks,
    mfaEvents
  ] = await Promise.all([
    AuditLog.getSecurityEvents(parseInt(period) * 24),
    AuditLog.getFailedLogins(parseInt(period) * 24),
    AuditLog.getSuspiciousActivity(parseInt(period) * 24),
    Transaction.find({
      riskScore: { $gte: 70 },
      createdAt: { $gte: since }
    }).populate('fromAccount', 'username'),
    AuditLog.find({
      eventType: { $in: ['account_locked', 'account_unlocked'] },
      timestamp: { $gte: since }
    }).populate('userId', 'username'),
    AuditLog.find({
      eventType: { $in: ['mfa_enabled', 'mfa_disabled', 'mfa_failed'] },
      timestamp: { $gte: since }
    }).populate('userId', 'username')
  ]);

  await logSecurityEvent(req, 'data_access', `Generated security report for ${period} days`, req.user._id, true);

  res.json({
    success: true,
    data: {
      period: `${period} days`,
      summary: {
        securityEventsCount: securityEvents.length,
        failedLoginsCount: failedLogins.length,
        suspiciousActivitiesCount: suspiciousActivities.length,
        highRiskTransactionsCount: highRiskTransactions.length,
        accountLocksCount: accountLocks.length,
        mfaEventsCount: mfaEvents.length
      },
      securityEvents,
      failedLogins,
      suspiciousActivities,
      highRiskTransactions,
      accountLocks,
      mfaEvents,
      generatedAt: new Date(),
      generatedBy: req.user.username
    }
  });
}));

// System settings (read-only for now)
router.get('/system/settings', asyncHandler(async (req, res) => {
  const settings = {
    passwordPolicy: {
      minLength: process.env.MIN_PASSWORD_LENGTH || 8,
      maxLength: process.env.MAX_PASSWORD_LENGTH || 128,
      expiryDays: process.env.PASSWORD_EXPIRY_DAYS || 90,
      historyCount: process.env.PASSWORD_HISTORY_COUNT || 5
    },
    mfa: {
      issuer: process.env.MFA_ISSUER || 'SecureApp',
      window: process.env.MFA_WINDOW || 2
    },
    rateLimit: {
      windowMs: process.env.RATE_LIMIT_WINDOW_MS || 900000,
      maxRequests: process.env.RATE_LIMIT_MAX_REQUESTS || 100
    },
    session: {
      maxAge: '30 minutes',
      secure: process.env.NODE_ENV === 'production'
    }
  };

  await logSecurityEvent(req, 'data_access', 'Viewed system settings', req.user._id, true);

  res.json({
    success: true,
    data: {
      settings
    }
  });
}));

module.exports = router;
