/**
 * Stripe Webhook Transaction Processing
 * Secure handlers for processing webhook-initiated transactions
 */
const express = require('express');
const router = express.Router();
const { asyncHandler } = require('../../middleware/errorHandler');
const Transaction = require('../../models/Transaction');
const User = require('../../models/User');
const AuditLog = require('../../models/AuditLog');
const TransactionService = require('../../services/transactionService');
const mongoose = require('mongoose');

/**
 * Process a webhook-initiated refund
 * This endpoint is called internally by webhook handlers
 */
async function processWebhookRefund(transactionId, refundData, initiatedBy = 'stripe_webhook') {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    // Find the original transaction
    const transaction = await Transaction.findOne({ transactionId }).session(session);
    
    if (!transaction) {
      throw new Error(`Original transaction ${transactionId} not found`);
    }
    
    if (transaction.status === 'refunded') {
      await session.abortTransaction();
      return { success: true, message: 'Transaction already refunded' };
    }
    
    // Create refund transaction
    const refundTransaction = new Transaction({
      type: 'refund',
      amount: refundData.amount,
      currency: transaction.currency,
      description: `Refund for transaction ${transactionId}: ${refundData.reason || 'Webhook initiated'}`,
      fromAccount: transaction.toAccount,
      toAccount: transaction.fromAccount,
      authenticationMethod: 'system',
      ipAddress: '0.0.0.0', // System-initiated
      userAgent: 'Stripe Webhook',
      createdBy: transaction.fromAccount, // Original user
      status: 'completed',
      processedAt: new Date(),
      externalTransactionId: refundData.refundId,
      stripeRefundId: refundData.refundId,
      stripeChargeId: transaction.stripeChargeId,
      stripePaymentIntentId: transaction.stripePaymentIntentId
    });
    
    // Calculate risk score and generate checksum
    refundTransaction.calculateRiskScore();
    refundTransaction.generateChecksum();
    
    // Update original transaction
    transaction.status = refundData.amount < transaction.amount ? 'partial_refund' : 'refunded';
    transaction.statusHistory.push({
      status: transaction.status,
      timestamp: new Date(),
      reason: refundData.reason || 'Webhook initiated refund'
    });
    
    transaction.refundDetails = {
      stripeRefundId: refundData.refundId,
      reason: refundData.reason || 'Webhook initiated',
      amount: refundData.amount,
      currency: transaction.currency,
      createdAt: new Date(),
      status: refundData.status || 'succeeded'
    };
    
    // Update balances if needed (in production, this would be handled by your financial ledger)
    if (transaction.toAccount) {
      const receiver = await User.findById(transaction.toAccount).session(session);
      if (receiver) {
        receiver.balance -= refundData.amount;
        await receiver.save({ session });
      }
    }
    
    if (transaction.fromAccount) {
      const sender = await User.findById(transaction.fromAccount).session(session);
      if (sender) {
        sender.balance += refundData.amount;
        await sender.save({ session });
      }
    }
    
    // Save transactions
    await refundTransaction.save({ session });
    await transaction.save({ session });
    
    // Log the webhook-initiated refund
    const auditLog = new AuditLog({
      eventType: 'webhook_refund_processed',
      userId: transaction.fromAccount,
      action: `Webhook initiated refund for transaction ${transaction.transactionId}`,
      resource: 'transaction',
      resourceId: transaction._id.toString(),
      ipAddress: '0.0.0.0',
      userAgent: 'Stripe Webhook',
      riskLevel: 'medium',
      metadata: {
        originalTransactionId: transaction.transactionId,
        refundTransactionId: refundTransaction.transactionId,
        stripeRefundId: refundData.refundId,
        amount: refundData.amount,
        initiatedBy
      },
      success: true
    });
    
    await auditLog.save({ session });
    
    // Commit the transaction
    await session.commitTransaction();
    
    return {
      success: true,
      refundTransactionId: refundTransaction.transactionId,
      originalTransactionId: transaction.transactionId,
      status: 'completed'
    };
  } catch (error) {
    // Roll back on error
    await session.abortTransaction();
    console.error('Webhook refund processing failed:', error);
    
    // Log the error
    const auditLog = new AuditLog({
      eventType: 'webhook_refund_failed',
      action: `Failed to process webhook refund for transaction ${transactionId}`,
      resource: 'transaction',
      ipAddress: '0.0.0.0',
      userAgent: 'Stripe Webhook',
      riskLevel: 'high',
      metadata: {
        originalTransactionId: transactionId,
        refundData,
        error: error.message,
        initiatedBy
      },
      success: false
    });
    await auditLog.save();
    
    throw error;
  } finally {
    session.endSession();
  }
}

/**
 * Process a webhook-initiated charge
 * This endpoint is called internally by webhook handlers for creating transactions from successful charges
 * that don't have a corresponding transaction in our system yet
 */
async function processWebhookCharge(chargeData, userId = null) {
  // Check if this charge already has a transaction
  const existingTransaction = await Transaction.findOne({ stripeChargeId: chargeData.chargeId });
  
  if (existingTransaction) {
    return { success: true, transactionId: existingTransaction.transactionId, exists: true };
  }
  
  // Create a new transaction
  try {
    // Find the user if userId is provided, or look up by Stripe customer ID
    let user = null;
    if (userId) {
      user = await User.findById(userId);
    } else if (chargeData.customerId) {
      user = await User.findOne({ stripeCustomerId: chargeData.customerId });
    }
    
    if (!user) {
      throw new Error('Could not identify user for this charge');
    }
    
    // Create transaction
    const transaction = new Transaction({
      type: 'deposit', // Assuming deposit as default for external charges
      amount: chargeData.amount,
      currency: chargeData.currency.toUpperCase(),
      description: chargeData.description || 'Stripe charge',
      toAccount: user._id,
      authenticationMethod: 'system',
      ipAddress: '0.0.0.0', // System-initiated
      userAgent: 'Stripe Webhook',
      createdBy: user._id,
      status: 'completed',
      processedAt: new Date(),
      externalTransactionId: chargeData.chargeId,
      stripeChargeId: chargeData.chargeId,
      stripePaymentIntentId: chargeData.paymentIntentId,
      stripePaymentMethodId: chargeData.paymentMethodId
    });
    
    // Calculate risk score and generate checksum
    transaction.calculateRiskScore();
    transaction.generateChecksum();
    
    // Update user balance (in production, this would be handled by your financial ledger)
    user.balance += chargeData.amount;
    
    // Save both records
    await transaction.save();
    await user.save();
    
    // Log the webhook-initiated charge
    const auditLog = new AuditLog({
      eventType: 'webhook_charge_processed',
      userId: user._id,
      action: `Webhook created transaction for charge ${chargeData.chargeId}`,
      resource: 'transaction',
      resourceId: transaction._id.toString(),
      ipAddress: '0.0.0.0',
      userAgent: 'Stripe Webhook',
      riskLevel: 'medium',
      metadata: {
        transactionId: transaction.transactionId,
        stripeChargeId: chargeData.chargeId,
        stripePaymentIntentId: chargeData.paymentIntentId,
        amount: chargeData.amount,
        paymentMethod: chargeData.paymentMethodType || 'unknown'
      },
      success: true
    });
    
    await auditLog.save();
    
    return {
      success: true,
      transactionId: transaction.transactionId,
      exists: false
    };
  } catch (error) {
    console.error('Webhook charge processing failed:', error);
    
    // Log the error
    const auditLog = new AuditLog({
      eventType: 'webhook_charge_failed',
      userId: userId,
      action: `Failed to process webhook charge ${chargeData.chargeId}`,
      resource: 'transaction',
      ipAddress: '0.0.0.0',
      userAgent: 'Stripe Webhook',
      riskLevel: 'high',
      metadata: {
        stripeChargeId: chargeData.chargeId,
        stripePaymentIntentId: chargeData.paymentIntentId,
        amount: chargeData.amount,
        error: error.message
      },
      success: false
    });
    await auditLog.save();
    
    throw error;
  }
}

module.exports = {
  processWebhookRefund,
  processWebhookCharge
};
