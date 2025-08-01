const express = require('express');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');

const User = require('../models/User');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');
const { 
  authenticateSession, 
  requireRole,
  requireTransactionAccess,
  requirePermission,
  requireMFA, 
  sensitiveOperationLimiter 
} = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityEvent } = require('../middleware/auth');

const router = express.Router();

// Import sub-routers for specific transaction functionality
const reconciliationRouter = require('./transaction/reconciliation');

// Validation rules for transactions
const transactionValidation = [
  body('type').isIn(['transfer', 'deposit', 'withdrawal', 'payment']).withMessage('Invalid transaction type'),
  body('amount').isFloat({ min: 0.01, max: 1000000 }).withMessage('Amount must be between $0.01 and $1,000,000'),
  body('description').optional().isLength({ max: 255 }).withMessage('Description must be less than 255 characters'),
  body('toAccountNumber').optional().matches(/^ACC[0-9]+[A-Z0-9]+$/).withMessage('Invalid account number format'),
  body('authenticationMethod').isIn(['password', 'mfa', 'biometric']).withMessage('Invalid authentication method')
];

// Get user transactions
router.get('/', authenticateSession, requirePermission('transactions', 'read'), asyncHandler(async (req, res) => {
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

// Import the transaction service
const TransactionService = require('../services/transactionService');

// Create new transaction with secure processing
router.post('/', authenticateSession, requirePermission('transactions', 'create'), requireMFA, sensitiveOperationLimiter, transactionValidation, asyncHandler(async (req, res) => {
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
    authenticationMethod = 'mfa',
    paymentMethodId
  } = req.body;

  const user = req.user;

  try {
    // Use the transaction service for secure processing
    const transaction = await TransactionService.processTransaction(
      {
        type,
        amount,
        currency,
        description,
        toAccountNumber,
        externalAccount,
        authenticationMethod,
        paymentMethodId
      },
      user,
      req
    );

    // Generate client response
    let clientResponse = {
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
    };
    
    // Add Stripe details if applicable
    if (transaction.paymentGatewayReference) {
      clientResponse.data.paymentInfo = {
        requiresAction: transaction.status === 'processing',
        clientSecret: transaction.paymentGatewayReference,
        status: transaction.status
      };
    }

    res.status(201).json(clientResponse);
  } catch (error) {
    await logSecurityEvent(req, 'transaction_created', `Transaction creation failed: ${error.message}`, user._id, false);
    
    // Return appropriate error message based on error type
    if (error.message.includes('Stripe') || error.code === 'card_error') {
      // Handle Stripe-specific errors
      return res.status(400).json({
        success: false,
        message: 'Payment processing failed',
        error: error.message,
        code: error.code || 'payment_error'
      });
    }
    
    throw error;
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

// Mount sub-routers
router.use('/reconciliation', reconciliationRouter);

module.exports = router;
