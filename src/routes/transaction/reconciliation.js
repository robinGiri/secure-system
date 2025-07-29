/**
 * Transaction Reconciliation Routes
 * Securely reconcile transactions with Stripe and handle discrepancies
 */
const express = require('express');
const { body, query, validationResult } = require('express-validator');
const { 
  authenticateSession, 
  authorize, 
  requireMFA 
} = require('../../middleware/auth');
const { asyncHandler } = require('../../middleware/errorHandler');
const TransactionService = require('../../services/transactionService');

const router = express.Router();

/**
 * Trigger reconciliation process with Stripe
 * Secure endpoint that requires admin privileges and MFA
 */
router.post('/stripe', 
  authenticateSession, 
  authorize('admin'), 
  requireMFA,
  [
    body('startDate').isISO8601().withMessage('Start date must be a valid ISO 8601 date'),
    body('endDate').isISO8601().withMessage('End date must be a valid ISO 8601 date'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { startDate, endDate } = req.body;
    const userId = req.user._id;
    
    try {
      const reconciliationResults = await TransactionService.reconcileWithStripe(
        new Date(startDate),
        new Date(endDate),
        userId
      );
      
      res.json({
        success: true,
        message: 'Reconciliation completed successfully',
        data: {
          ...reconciliationResults,
          startDate,
          endDate,
          reconciledBy: req.user.username,
          reconciledAt: new Date().toISOString()
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Reconciliation failed',
        error: error.message
      });
    }
  })
);

/**
 * Get reconciliation history
 */
router.get('/history',
  authenticateSession,
  authorize('admin'),
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { page = 1, limit = 20 } = req.query;
    
    // Find all reconciled transactions grouped by reconciliationId
    const Transaction = require('../../models/Transaction');
    
    const reconciliations = await Transaction.aggregate([
      { $match: { isReconciled: true } },
      { $sort: { 'reconciliationDetails.reconciledAt': -1 } },
      { 
        $group: {
          _id: '$reconciliationDetails.reconciliationId',
          reconciledAt: { $first: '$reconciliationDetails.reconciledAt' },
          reconciliationMethod: { $first: '$reconciliationDetails.reconciliationMethod' },
          reconciledBy: { $first: '$reconciliationDetails.reconciledBy' },
          notes: { $first: '$reconciliationDetails.notes' },
          count: { $sum: 1 }
        }
      },
      { $sort: { reconciledAt: -1 } },
      { $skip: (parseInt(page) - 1) * parseInt(limit) },
      { $limit: parseInt(limit) }
    ]);
    
    const total = await Transaction.aggregate([
      { $match: { isReconciled: true } },
      { $group: { _id: '$reconciliationDetails.reconciliationId' } },
      { $count: 'total' }
    ]);
    
    res.json({
      success: true,
      data: {
        reconciliations,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: total[0]?.total || 0,
          pages: Math.ceil((total[0]?.total || 0) / parseInt(limit))
        }
      }
    });
  })
);

/**
 * Get reconciliation details
 */
router.get('/history/:reconciliationId',
  authenticateSession,
  authorize('admin'),
  asyncHandler(async (req, res) => {
    const { reconciliationId } = req.params;
    
    const Transaction = require('../../models/Transaction');
    
    const transactions = await Transaction.find({
      'reconciliationDetails.reconciliationId': reconciliationId
    }).sort({ createdAt: -1 });
    
    if (!transactions.length) {
      return res.status(404).json({
        success: false,
        message: 'Reconciliation not found'
      });
    }
    
    const reconciliationDetails = transactions[0].reconciliationDetails;
    
    // Get the user who reconciled
    const User = require('../../models/User');
    let reconciledByUser = null;
    
    if (reconciliationDetails.reconciledBy) {
      reconciledByUser = await User.findById(reconciliationDetails.reconciledBy)
        .select('username firstName lastName');
    }
    
    res.json({
      success: true,
      data: {
        reconciliationId,
        reconciledAt: reconciliationDetails.reconciledAt,
        reconciliationMethod: reconciliationDetails.reconciliationMethod,
        reconciledBy: reconciledByUser,
        notes: reconciliationDetails.notes,
        transactions: transactions.map(t => ({
          transactionId: t.transactionId,
          type: t.type,
          amount: t.amount,
          currency: t.currency,
          status: t.status,
          createdAt: t.createdAt,
          externalTransactionId: t.externalTransactionId,
          stripeChargeId: t.stripeChargeId,
          stripePaymentIntentId: t.stripePaymentIntentId
        }))
      }
    });
  })
);

module.exports = router;
