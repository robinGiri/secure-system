const express = require('express');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');

const User = require('../models/User');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');
const { 
  authenticateSession, 
  requireMFA, 
  sensitiveOperationLimiter 
} = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityEvent } = require('../middleware/auth');

const router = express.Router();

// Validation rules for transactions
const transactionValidation = [
  body('type').isIn(['transfer', 'deposit', 'withdrawal', 'payment']).withMessage('Invalid transaction type'),
  body('amount').isFloat({ min: 0.01, max: 1000000 }).withMessage('Amount must be between $0.01 and $1,000,000'),
  body('description').optional().isLength({ max: 255 }).withMessage('Description must be less than 255 characters'),
  body('toAccountNumber').optional().isLength({ min: 8, max: 20 }).withMessage('Invalid account number'),
  body('authenticationMethod').isIn(['password', 'mfa', 'biometric']).withMessage('Invalid authentication method')
];

// Get user transactions
router.get('/', authenticateSession, asyncHandler(async (req, res) => {
  const { 
    page = 1, 
    limit = 20, 
    type, 
    status, 
    startDate, 
    endDate,
    minAmount,
    maxAmount 
  } = req.query;

  const userId = req.user._id;
  const filter = {
    $or: [
      { fromAccount: userId },
      { toAccount: userId }
    ]
  };

  // Apply filters
  if (type) filter.type = type;
  if (status) filter.status = status;
  if (minAmount || maxAmount) {
    filter.amount = {};
    if (minAmount) filter.amount.$gte = parseFloat(minAmount);
    if (maxAmount) filter.amount.$lte = parseFloat(maxAmount);
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
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit));

  const total = await Transaction.countDocuments(filter);

  // Mark transactions as viewed
  await logSecurityEvent(req, 'data_access', `Viewed transactions (page ${page})`, userId, true);

  res.json({
    success: true,
    data: {
      transactions: transactions.map(transaction => ({
        id: transaction._id,
        transactionId: transaction.transactionId,
        type: transaction.type,
        amount: transaction.amount,
        currency: transaction.currency,
        description: transaction.description,
        status: transaction.status,
        fromAccount: transaction.fromAccount,
        toAccount: transaction.toAccount,
        createdAt: transaction.createdAt,
        processedAt: transaction.processedAt,
        fees: transaction.totalFees,
        riskScore: transaction.riskScore,
        isIncoming: transaction.toAccount?._id?.toString() === userId.toString()
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    }
  });
}));

// Get single transaction
router.get('/:transactionId', authenticateSession, asyncHandler(async (req, res) => {
  const { transactionId } = req.params;
  const userId = req.user._id;

  const transaction = await Transaction.findOne({
    $or: [
      { transactionId, fromAccount: userId },
      { transactionId, toAccount: userId }
    ]
  })
  .populate('fromAccount', 'username accountNumber firstName lastName')
  .populate('toAccount', 'username accountNumber firstName lastName')
  .populate('processedBy', 'username');

  if (!transaction) {
    return res.status(404).json({
      success: false,
      message: 'Transaction not found'
    });
  }

  await logSecurityEvent(req, 'data_access', `Viewed transaction ${transactionId}`, userId, true);

  res.json({
    success: true,
    data: {
      transaction: {
        id: transaction._id,
        transactionId: transaction.transactionId,
        type: transaction.type,
        amount: transaction.amount,
        currency: transaction.currency,
        description: transaction.description,
        status: transaction.status,
        statusHistory: transaction.statusHistory,
        fromAccount: transaction.fromAccount,
        toAccount: transaction.toAccount,
        externalAccount: transaction.externalAccount,
        authenticationMethod: transaction.authenticationMethod,
        riskScore: transaction.riskScore,
        riskFactors: transaction.riskFactors,
        fees: transaction.fees,
        totalFees: transaction.totalFees,
        balanceBefore: transaction.balanceBefore,
        balanceAfter: transaction.balanceAfter,
        createdAt: transaction.createdAt,
        processedAt: transaction.processedAt,
        processedBy: transaction.processedBy,
        processingTime: transaction.processingTime
      }
    }
  });
}));

// Create new transaction
router.post('/', authenticateSession, requireMFA, sensitiveOperationLimiter, transactionValidation, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { 
    type, 
    amount, 
    currency = 'USD', 
    description, 
    toAccountNumber,
    externalAccount,
    authenticationMethod = 'mfa'
  } = req.body;

  const user = req.user;
  const session = await mongoose.startSession();

  try {
    await session.withTransaction(async () => {
      // Validate transaction type and requirements
      if (['transfer', 'withdrawal', 'payment'].includes(type)) {
        if (user.balance < amount) {
          throw new Error('Insufficient funds');
        }
      }

      let toAccount = null;
      if (type === 'transfer' && toAccountNumber) {
        toAccount = await User.findOne({ accountNumber: toAccountNumber }).session(session);
        if (!toAccount) {
          throw new Error('Recipient account not found');
        }
        if (toAccount._id.toString() === user._id.toString()) {
          throw new Error('Cannot transfer to your own account');
        }
      }

      // Create transaction
      const transaction = new Transaction({
        type,
        amount,
        currency,
        description,
        fromAccount: ['transfer', 'withdrawal', 'payment'].includes(type) ? user._id : null,
        toAccount: type === 'transfer' ? toAccount?._id : (type === 'deposit' ? user._id : null),
        externalAccount,
        authenticationMethod,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        createdBy: user._id,
        balanceBefore: {
          fromAccount: user.balance,
          toAccount: toAccount?.balance || 0
        }
      });

      // Calculate risk score
      transaction.calculateRiskScore();

      // Generate checksum
      transaction.generateChecksum();

      // Encrypt sensitive data if needed
      if (externalAccount) {
        transaction.encryptSensitiveData(externalAccount);
      }

      // Update balances
      if (['transfer', 'withdrawal', 'payment'].includes(type)) {
        user.balance -= amount;
        await user.save({ session });
      }

      if (type === 'transfer' && toAccount) {
        toAccount.balance += amount;
        await toAccount.save({ session });
      }

      if (type === 'deposit') {
        user.balance += amount;
        await user.save({ session });
      }

      // Set balance after
      transaction.balanceAfter = {
        fromAccount: user.balance,
        toAccount: toAccount?.balance || 0
      };

      // Set initial status based on risk score
      if (transaction.riskScore >= 70) {
        transaction.status = 'pending';
        transaction.fraudCheckStatus = 'manual_review';
      } else if (transaction.riskScore >= 40) {
        transaction.status = 'processing';
      } else {
        transaction.status = 'completed';
        transaction.processedAt = new Date();
        transaction.processedBy = user._id;
      }

      await transaction.save({ session });

      // Log transaction creation
      const auditLog = new AuditLog({
        eventType: 'transaction_created',
        userId: user._id,
        username: user.username,
        userRole: user.role,
        sessionId: req.sessionID,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        action: `Created ${type} transaction for $${amount}`,
        resource: 'transaction',
        resourceId: transaction._id.toString(),
        riskLevel: transaction.riskScore >= 40 ? 'high' : 'medium',
        metadata: {
          transactionId: transaction.transactionId,
          amount,
          type,
          toAccount: toAccount?.accountNumber,
          riskScore: transaction.riskScore
        },
        success: true
      });

      await auditLog.save({ session });

      res.status(201).json({
        success: true,
        message: 'Transaction created successfully',
        data: {
          transaction: {
            id: transaction._id,
            transactionId: transaction.transactionId,
            type: transaction.type,
            amount: transaction.amount,
            status: transaction.status,
            riskScore: transaction.riskScore,
            createdAt: transaction.createdAt
          }
        }
      });
    });
  } catch (error) {
    await logSecurityEvent(req, 'transaction_created', `Transaction creation failed: ${error.message}`, user._id, false);
    throw error;
  } finally {
    await session.endSession();
  }
}));

// Cancel transaction (if pending)
router.patch('/:transactionId/cancel', authenticateSession, sensitiveOperationLimiter, asyncHandler(async (req, res) => {
  const { transactionId } = req.params;
  const userId = req.user._id;

  const transaction = await Transaction.findOne({
    transactionId,
    fromAccount: userId,
    status: { $in: ['pending', 'processing'] }
  });

  if (!transaction) {
    return res.status(404).json({
      success: false,
      message: 'Transaction not found or cannot be cancelled'
    });
  }

  const session = await mongoose.startSession();

  try {
    await session.withTransaction(async () => {
      // Reverse balance changes if transaction was processing
      if (transaction.status === 'processing' || transaction.status === 'pending') {
        const user = await User.findById(userId).session(session);
        
        if (['transfer', 'withdrawal', 'payment'].includes(transaction.type)) {
          user.balance += transaction.amount;
          await user.save({ session });
        }

        if (transaction.type === 'transfer' && transaction.toAccount) {
          const toUser = await User.findById(transaction.toAccount).session(session);
          if (toUser) {
            toUser.balance -= transaction.amount;
            await toUser.save({ session });
          }
        }
      }

      // Update transaction status
      transaction.status = 'cancelled';
      transaction.processedAt = new Date();
      transaction.processedBy = userId;
      await transaction.save({ session });

      // Log the cancellation
      const auditLog = new AuditLog({
        eventType: 'transaction_updated',
        userId,
        username: req.user.username,
        userRole: req.user.role,
        sessionId: req.sessionID,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        action: `Cancelled transaction ${transactionId}`,
        resource: 'transaction',
        resourceId: transaction._id.toString(),
        oldValues: { status: 'processing' },
        newValues: { status: 'cancelled' },
        success: true
      });

      await auditLog.save({ session });

      res.json({
        success: true,
        message: 'Transaction cancelled successfully',
        data: {
          transactionId: transaction.transactionId,
          status: transaction.status
        }
      });
    });
  } catch (error) {
    await logSecurityEvent(req, 'transaction_updated', `Transaction cancellation failed: ${error.message}`, userId, false);
    throw error;
  } finally {
    await session.endSession();
  }
}));

// Get transaction summary/analytics
router.get('/analytics/summary', authenticateSession, asyncHandler(async (req, res) => {
  const { period = '30' } = req.query; // days
  const userId = req.user._id;
  const startDate = new Date(Date.now() - parseInt(period) * 24 * 60 * 60 * 1000);

  const summary = await Transaction.getTransactionSummary(userId, startDate, new Date());

  // Get total balance
  const user = await User.findById(userId).select('balance');

  // Get recent transactions count
  const recentTransactions = await Transaction.countDocuments({
    $or: [{ fromAccount: userId }, { toAccount: userId }],
    createdAt: { $gte: startDate }
  });

  // Get pending transactions
  const pendingTransactions = await Transaction.countDocuments({
    fromAccount: userId,
    status: { $in: ['pending', 'processing'] }
  });

  res.json({
    success: true,
    data: {
      summary,
      currentBalance: user.balance,
      recentTransactionsCount: recentTransactions,
      pendingTransactionsCount: pendingTransactions,
      period: `${period} days`
    }
  });
}));

// Export transactions (CSV format)
router.get('/export', authenticateSession, asyncHandler(async (req, res) => {
  const { startDate, endDate, format = 'json' } = req.query;
  const userId = req.user._id;

  const filter = {
    $or: [{ fromAccount: userId }, { toAccount: userId }]
  };

  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }

  const transactions = await Transaction.find(filter)
    .populate('fromAccount', 'accountNumber')
    .populate('toAccount', 'accountNumber')
    .select('transactionId type amount currency description status createdAt processedAt')
    .sort({ createdAt: -1 })
    .limit(1000); // Limit for security

  await logSecurityEvent(req, 'data_export', `Exported ${transactions.length} transactions`, userId, true);

  if (format === 'csv') {
    const csv = [
      'Transaction ID,Type,Amount,Currency,Description,Status,Created At,Processed At',
      ...transactions.map(t => 
        `${t.transactionId},${t.type},${t.amount},${t.currency},"${t.description || ''}",${t.status},${t.createdAt.toISOString()},${t.processedAt?.toISOString() || ''}`
      )
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=transactions.csv');
    res.send(csv);
  } else {
    res.json({
      success: true,
      data: {
        transactions,
        exportedAt: new Date(),
        count: transactions.length
      }
    });
  }
}));

module.exports = router;
