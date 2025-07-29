/**
 * Stripe Webhook Handler
 * Securely processes Stripe webhook events for transaction updates
 */
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Stripe webhook endpoint with enhanced security
router.post('/webhook', express.raw({type: 'application/json'}), asyncHandler(async (req, res) => {
  const signature = req.headers['stripe-signature'];
  const ip = req.ip;
  
  // Rate limiting for webhook endpoint
  if (!stripeRateLimit.check('webhook', 100, 60000)) { // 100 webhooks per minute
    await logWebhookEvent('stripe_webhook_rate_limit', 'Rate limit exceeded for webhook endpoint', null, 'high', req);
    return res.status(429).send('Rate limit exceeded');
  }
  
  // IP-based security check - optional, but helpful to block unexpected sources
  // In production, you would maintain a list of Stripe IPs or use other verification
  // const allowedIps = ['3.18.12.63', '3.130.192.231', '13.235.14.237', '13.235.122.149'];
  // if (!allowedIps.includes(ip)) {
  //   await logWebhookEvent('stripe_webhook_invalid_ip', `Webhook called from invalid IP: ${ip}`, null, 'high', req);
  //   return res.status(403).send('Invalid source IP');
  // }
  
  let event;
  try {
    // Enhanced webhook signature verification with timing-safe comparison
    if (!signature) {
      await logWebhookEvent('stripe_webhook_error', 'Missing Stripe signature', null, 'high', req);
      return res.status(400).send('Missing Stripe signature');
    }
    
    // Create a secure context for webhook processing
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) {
      await logWebhookEvent('stripe_webhook_config_error', 'Webhook secret not configured', null, 'critical', req);
      return res.status(500).send('Webhook configuration error');
    }
    
    try {
      // Use our custom signature validation first for enhanced security
      const { validateWebhookSignature } = require('../utils/stripeUtils');
      
      const validationResult = validateWebhookSignature({
        payload: req.body.toString(),
        signature,
        secret: webhookSecret,
        tolerance: 300 // 5 minutes
      });
      
      if (!validationResult.isValid) {
        // Log detailed signature validation failure
        await logWebhookEvent(
          'stripe_webhook_error', 
          `Enhanced signature verification failed: ${validationResult.error}`, 
          null, 
          'high', 
          req,
          {
            signatureHeader: signature?.substring(0, 10) + '...' || 'missing',
            error: validationResult.error,
            code: validationResult.code,
            details: validationResult.details,
            timestamp: Date.now()
          }
        );
        return res.status(400).send(`Webhook Error: ${validationResult.error}`);
      }
      
      // If our validation passes, still use Stripe's official validation as a second layer
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        webhookSecret
      );
    } catch (err) {
      // Log detailed signature validation failure
      await logWebhookEvent(
        'stripe_webhook_error', 
        `Stripe signature verification failed: ${err.message}`, 
        null, 
        'high', 
        req,
        {
          signatureHeader: signature?.substring(0, 10) + '...' || 'missing',
          error: err.message,
          timestamp: Date.now()
        }
      );
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
  } catch (err) {
    await logWebhookEvent('stripe_webhook_error', `Webhook processing error: ${err.message}`, null, 'high', req);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  
  // Log the received event
  await logWebhookEvent(
    'stripe_webhook_received',
    `Received Stripe event: ${event.type}`,
    null,
    'low',
    req,
    { eventId: event.id, eventType: event.type }
  );
  
  try {
    // Handle specific events with enhanced error handling
    switch (event.type) {
      case 'payment_intent.succeeded':
        await handlePaymentIntentSucceeded(event.data.object, req);
        break;
        
      case 'payment_intent.payment_failed':
        await handlePaymentIntentFailed(event.data.object, req);
        break;
        
      case 'payout.paid':
        await handlePayoutPaid(event.data.object, req);
        break;
        
      case 'payout.failed':
        await handlePayoutFailed(event.data.object, req);
        break;
        
      // Enhanced handling for additional events
      case 'charge.succeeded':
        await handleChargeSucceeded(event.data.object, req);
        break;
        
      case 'charge.failed':
        await handleChargeFailed(event.data.object, req);
        break;
        
      case 'charge.dispute.created':
        await handleDisputeCreated(event.data.object, req);
        break;
        
      // Handle refund events
      case 'charge.refunded':
        await handleChargeRefunded(event.data.object, req);
        break;
        
      case 'charge.refund.updated':
        await handleRefundUpdated(event.data.object, req);
        break;
        
      // Handle additional payment processing events
      case 'payment_intent.created':
        await handlePaymentIntentCreated(event.data.object, req);
        break;
        
      case 'payment_intent.canceled':
        await handlePaymentIntentCanceled(event.data.object, req);
        break;
        
      case 'payment_method.attached':
        await handlePaymentMethodAttached(event.data.object, req);
        break;
        
      case 'payment_method.detached':
        await handlePaymentMethodDetached(event.data.object, req);
        break;
        
      // Handle additional dispute events
      case 'charge.dispute.closed':
        await handleDisputeClosed(event.data.object, req);
        break;
        
      case 'charge.dispute.updated':
        await handleDisputeUpdated(event.data.object, req);
        break;
        
      default:
        // Log unhandled event types with detailed data for future implementation
        await logWebhookEvent(
          'unhandled_stripe_event',
          `Unhandled Stripe event type: ${event.type}`,
          null,
          'medium',
          req,
          {
            eventId: event.id,
            eventType: event.type,
            objectType: event.data.object.object,
            timestamp: new Date().toISOString()
          }
        );
    }
  } catch (error) {
    // Log processing errors but still return 200 to Stripe
    await logWebhookEvent(
      'stripe_webhook_processing_error',
      `Error processing webhook ${event.type}: ${error.message}`,
      null,
      'high',
      req,
      {
        eventId: event.id, 
        eventType: event.type,
        error: error.message,
        stack: error.stack?.substring(0, 200) // Include partial stack trace for debugging
      }
    );
  }
  
  // Return a 200 response to acknowledge receipt of the event
  // Important: Always return 200 to Stripe even for events we don't process
  // to prevent unnecessary retries
  res.send({received: true});
}));

/**
 * Handle successful payment intent 
 */
async function handlePaymentIntentSucceeded(paymentIntent) {
  // Find associated transaction
  const transaction = await Transaction.findOne({ 
    externalTransactionId: paymentIntent.id 
  });
  
  if (!transaction) {
    console.error(`No transaction found for payment intent: ${paymentIntent.id}`);
    return;
  }
  
  // Update transaction status
  transaction.status = 'completed';
  transaction.processedAt = new Date();
  transaction.statusHistory.push({
    status: 'completed',
    timestamp: new Date(),
    reason: 'Payment confirmed by Stripe'
  });
  
  await transaction.save();
  
  // Log the event
  const auditLog = new AuditLog({
    eventType: 'transaction_updated',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Transaction ${transaction.transactionId} completed via Stripe`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    metadata: {
      stripeEvent: 'payment_intent.succeeded',
      paymentIntentId: paymentIntent.id,
      amount: paymentIntent.amount / 100,
      currency: paymentIntent.currency
    },
    success: true
  });
  
  await auditLog.save();
}

/**
 * Handle failed payment intent
 */
async function handlePaymentIntentFailed(paymentIntent) {
  // Find associated transaction
  const transaction = await Transaction.findOne({ 
    externalTransactionId: paymentIntent.id 
  });
  
  if (!transaction) {
    console.error(`No transaction found for payment intent: ${paymentIntent.id}`);
    return;
  }
  
  // Update transaction status
  transaction.status = 'failed';
  transaction.statusHistory.push({
    status: 'failed',
    timestamp: new Date(),
    reason: paymentIntent.last_payment_error?.message || 'Payment failed'
  });
  
  await transaction.save();
  
  // Revert balance changes if needed
  if (transaction.type === 'deposit' && transaction.toAccount) {
    const user = await User.findById(transaction.toAccount);
    if (user) {
      user.balance -= transaction.amount;
      await user.save();
    }
  }
  
  // Log the event
  const auditLog = new AuditLog({
    eventType: 'transaction_failed',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Transaction ${transaction.transactionId} failed via Stripe`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    riskLevel: 'medium',
    metadata: {
      stripeEvent: 'payment_intent.payment_failed',
      paymentIntentId: paymentIntent.id,
      error: paymentIntent.last_payment_error?.message,
      errorCode: paymentIntent.last_payment_error?.code
    },
    success: false
  });
  
  await auditLog.save();
}

/**
 * Handle successful payout
 */
async function handlePayoutPaid(payout) {
  // Update associated withdrawal transaction
  const transaction = await Transaction.findOne({
    externalTransactionId: payout.id
  });
  
  if (transaction) {
    transaction.status = 'completed';
    transaction.processedAt = new Date();
    await transaction.save();
    
    // Log the successful payout
    const auditLog = new AuditLog({
      eventType: 'payout_completed',
      userId: transaction.fromAccount,
      action: `Payout completed for transaction ${transaction.transactionId}`,
      resource: 'transaction',
      resourceId: transaction._id.toString(),
      metadata: {
        stripeEvent: 'payout.paid',
        payoutId: payout.id,
        amount: payout.amount / 100,
        currency: payout.currency
      },
      success: true
    });
    
    await auditLog.save();
  }
}

/**
 * Handle failed payout
 */
async function handlePayoutFailed(payout) {
  // Update associated withdrawal transaction
  const transaction = await Transaction.findOne({
    externalTransactionId: payout.id
  });
  
  if (transaction) {
    transaction.status = 'failed';
    transaction.statusHistory.push({
      status: 'failed',
      timestamp: new Date(),
      reason: payout.failure_message || 'Payout failed'
    });
    await transaction.save();
    
    // Restore user balance
    const user = await User.findById(transaction.fromAccount);
    if (user) {
      user.balance += transaction.amount;
      await user.save();
    }
    
    // Log the failed payout
    const auditLog = new AuditLog({
      eventType: 'payout_failed',
      userId: transaction.fromAccount,
      action: `Payout failed for transaction ${transaction.transactionId}`,
      resource: 'transaction',
      resourceId: transaction._id.toString(),
      riskLevel: 'medium',
      metadata: {
        stripeEvent: 'payout.failed',
        payoutId: payout.id,
        error: payout.failure_message,
        errorCode: payout.failure_code
      },
      success: false
    });
    
    await auditLog.save();
  }
}

/**
 * Handle successful charge
 */
async function handleChargeSucceeded(charge, req) {
  const { processWebhookCharge } = require('./transaction/stripe-webhook');
  
  // Find associated transaction by payment intent
  const transaction = await Transaction.findOne({ 
    $or: [
      { externalTransactionId: charge.payment_intent },
      { stripePaymentIntentId: charge.payment_intent },
      { stripeChargeId: charge.id }
    ]
  });
  
  if (!transaction) {
    // No transaction found - this might be a charge created outside our system
    // Let's try to create a transaction record for it
    try {
      const result = await processWebhookCharge({
        chargeId: charge.id,
        paymentIntentId: charge.payment_intent,
        amount: charge.amount / 100,
        currency: charge.currency,
        customerId: charge.customer,
        paymentMethodId: charge.payment_method,
        paymentMethodType: charge.payment_method_details?.type || 'unknown',
        description: charge.description || 'Stripe charge'
      });
      
      await logWebhookEvent(
        'charge_transaction_created',
        `Created transaction record for external charge: ${charge.id}`,
        null,
        'medium',
        req,
        {
          stripeEvent: 'charge.succeeded',
          chargeId: charge.id,
          transactionId: result.transactionId,
          amount: charge.amount / 100
        }
      );
    } catch (error) {
      await logWebhookEvent(
        'charge_without_transaction',
        `No transaction found for charge: ${charge.id} and failed to create one: ${error.message}`,
        null,
        'high',
        req,
        {
          stripeEvent: 'charge.succeeded',
          chargeId: charge.id,
          paymentIntentId: charge.payment_intent,
          error: error.message
        }
      );
    }
    return;
  }
  
  // Update the transaction with charge ID if not already set
  if (!transaction.stripeChargeId) {
    transaction.stripeChargeId = charge.id;
    await transaction.save();
  }
  
  // Log successful charge with full details
  const auditLog = new AuditLog({
    eventType: 'charge_succeeded',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Charge succeeded for transaction ${transaction.transactionId}`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    metadata: {
      stripeEvent: 'charge.succeeded',
      chargeId: charge.id,
      paymentIntentId: charge.payment_intent,
      amount: charge.amount / 100,
      currency: charge.currency,
      paymentMethod: charge.payment_method_details?.type || 'unknown',
      receiptUrl: charge.receipt_url || null,
      cardBrand: charge.payment_method_details?.card?.brand || null,
      cardLast4: charge.payment_method_details?.card?.last4 || null,
      captured: charge.captured,
      statementDescriptor: charge.statement_descriptor || null
    },
    success: true
  });
  
  await auditLog.save();
}

/**
 * Handle failed charge
 */
async function handleChargeFailed(charge) {
  // Find associated transaction
  const transaction = await Transaction.findOne({ 
    externalTransactionId: charge.payment_intent 
  });
  
  if (!transaction) {
    await logWebhookEvent(
      'charge_failed_without_transaction',
      `No transaction found for failed charge: ${charge.id}`,
      null,
      'high',
      { ip: '0.0.0.0', get: () => 'Stripe Webhook' }
    );
    return;
  }
  
  // Update transaction with detailed failure reason
  transaction.statusHistory.push({
    status: 'failed',
    timestamp: new Date(),
    reason: charge.failure_message || 'Charge failed',
    code: charge.failure_code || 'unknown'
  });
  
  // Add failure details to transaction metadata
  transaction.metadata = transaction.metadata || {};
  transaction.metadata.failureDetails = {
    message: charge.failure_message,
    code: charge.failure_code,
    outcome: charge.outcome,
    riskLevel: charge.outcome?.risk_level
  };
  
  await transaction.save();
  
  // Log detailed audit of the charge failure
  const auditLog = new AuditLog({
    eventType: 'charge_failed',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Charge failed for transaction ${transaction.transactionId}`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    riskLevel: 'high',
    metadata: {
      stripeEvent: 'charge.failed',
      chargeId: charge.id,
      paymentIntentId: charge.payment_intent,
      error: charge.failure_message,
      errorCode: charge.failure_code,
      paymentMethod: charge.payment_method_details?.type || 'unknown',
      amount: charge.amount / 100,
      currency: charge.currency
    },
    success: false
  });
  
  await auditLog.save();
}

/**
 * Handle dispute created
 */
async function handleDisputeCreated(dispute) {
  // Find charge and associated transaction
  const transaction = await Transaction.findOne({ 
    externalTransactionId: dispute.payment_intent 
  });
  
  if (!transaction) {
    await logWebhookEvent(
      'dispute_without_transaction',
      `No transaction found for disputed charge: ${dispute.charge}`,
      null,
      'high',
      { ip: '0.0.0.0', get: () => 'Stripe Webhook' }
    );
    return;
  }
  
  // Update transaction with dispute information
  transaction.status = 'disputed';
  transaction.disputeDetails = {
    stripeDisputeId: dispute.id,
    reason: dispute.reason,
    status: dispute.status,
    amount: dispute.amount / 100,
    currency: dispute.currency,
    createdAt: new Date(dispute.created * 1000)
  };
  
  transaction.statusHistory.push({
    status: 'disputed',
    timestamp: new Date(),
    reason: `Payment disputed: ${dispute.reason}`
  });
  
  await transaction.save();
  
  // High priority audit log for dispute
  const auditLog = new AuditLog({
    eventType: 'transaction_disputed',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Dispute created for transaction ${transaction.transactionId}`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    riskLevel: 'high',
    metadata: {
      stripeEvent: 'charge.dispute.created',
      disputeId: dispute.id,
      chargeId: dispute.charge,
      reason: dispute.reason,
      status: dispute.status,
      amount: dispute.amount / 100,
      currency: dispute.currency
    },
    success: false
  });
  
  await auditLog.save();
}

/**
 * Log webhook events securely with enhanced context and security information
 * @param {string} eventType - Type of webhook event
 * @param {string} action - Action description
 * @param {string} userId - Associated user ID
 * @param {string} riskLevel - Risk level of the event
 * @param {Object} req - Request object
 * @param {Object} additionalData - Additional data to log
 * @returns {Promise<void>}
 */
async function logWebhookEvent(eventType, action, userId, riskLevel, req, additionalData = {}) {
  try {
    // Generate a unique event ID
    const eventId = `webhook_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Get only safe headers to log
    const safeHeaders = {
      signature: req.headers['stripe-signature'] ? 'present' : 'missing',
      contentType: req.headers['content-type'],
      userAgent: req.headers['user-agent']?.substring(0, 100) || 'none' // Truncate to avoid oversized logs
    };
    
    // Create structured metadata
    const metadata = {
      eventId,
      headers: safeHeaders,
      ipAddress: req.ip,
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      ...additionalData // Include additional context data
    };
    
    // Add security context
    if (riskLevel === 'high' || riskLevel === 'critical') {
      metadata.securityContext = {
        sourceGeoIP: req.ipInfo?.country || 'unknown',
        requestMethod: req.method,
        requestPath: req.path,
        timeReceived: new Date().toISOString()
      };
    }
    
    // Create the audit log with enhanced details
    const auditLog = new AuditLog({
      eventType,
      userId,
      action,
      resource: 'stripe_webhook',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')?.substring(0, 200) || 'none', // Truncate very long user agents
      riskLevel,
      metadata,
      success: riskLevel !== 'high' && riskLevel !== 'critical'
    });
    
    await auditLog.save();
    
    // For critical events, write to a separate log file or alerting system
    if (riskLevel === 'critical') {
      console.error(`CRITICAL STRIPE WEBHOOK EVENT: ${eventType} - ${action}`);
      // In a production system, this would trigger immediate alerts
      // alertingSystem.triggerAlert('critical_webhook_event', {eventId, eventType, action});
    }
  } catch (error) {
    // Failsafe logging if database operation fails
    console.error('Failed to log webhook event:', error);
    
    // As a fallback, write to the filesystem
    const fs = require('fs').promises;
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        eventType,
        action,
        riskLevel,
        error: error.message
      };
      await fs.appendFile('logs/webhook-errors.log', JSON.stringify(logEntry) + '\n');
    } catch (fsError) {
      // Last resort logging
      console.error('Critical error logging webhook event:', fsError);
    }
  }
}

// Rate limiting for Stripe API operations
const stripeRateLimit = {
  operations: new Map(),
  check: function(operationType, limit = 10, windowMs = 60000) {
    const now = Date.now();
    const key = operationType;
    const entry = this.operations.get(key) || { count: 0, startTime: now };
    
    // Reset if window has passed
    if (now - entry.startTime > windowMs) {
      entry.count = 1;
      entry.startTime = now;
      this.operations.set(key, entry);
      return true;
    }
    
    // Increment and check
    entry.count++;
    this.operations.set(key, entry);
    
    return entry.count <= limit;
  }
};

/**
 * Handle charge refunded event
 */
async function handleChargeRefunded(charge, req) {
  const { processWebhookRefund } = require('./transaction/stripe-webhook');
  
  // Find the transaction for this charge
  const transaction = await Transaction.findOne({
    stripeChargeId: charge.id
  });
  
  if (!transaction) {
    await logWebhookEvent(
      'refund_without_transaction',
      `No transaction found for refunded charge: ${charge.id}`,
      null,
      'medium',
      req
    );
    return;
  }
  
  // Check if transaction is already marked as refunded
  if (transaction.status === 'refunded') {
    return; // Already processed
  }
  
  const refundAmount = charge.amount_refunded / 100;
  const refundId = charge.refunds?.data[0]?.id;
  const refundReason = charge.refunds?.data[0]?.reason || 'Processed by Stripe';
  
  try {
    // Use the secure webhook refund processor
    await processWebhookRefund(
      transaction.transactionId,
      {
        amount: refundAmount,
        refundId: refundId,
        reason: refundReason,
        status: charge.refunds?.data[0]?.status || 'succeeded'
      },
      'stripe_webhook_charge_refunded'
    );
    
    // Log successful webhook processing
    await logWebhookEvent(
      'refund_processed',
      `Refund processed for transaction ${transaction.transactionId}`,
      transaction.fromAccount || transaction.toAccount,
      'medium',
      req,
      {
        stripeEvent: 'charge.refunded',
        chargeId: charge.id,
        refundId: refundId,
        amount: refundAmount,
        isPartialRefund: refundAmount < (charge.amount / 100)
      }
    );
  } catch (error) {
    // Log error but don't throw - we still want to return 200 to Stripe
    await logWebhookEvent(
      'refund_processing_error',
      `Error processing refund: ${error.message}`,
      transaction.fromAccount || transaction.toAccount,
      'high',
      req,
      {
        stripeEvent: 'charge.refunded',
        chargeId: charge.id,
        transactionId: transaction.transactionId,
        error: error.message
      }
    );
  }
}

/**
 * Handle refund updated event
 */
async function handleRefundUpdated(refund, req) {
  // Find transaction with this refund
  const transaction = await Transaction.findOne({
    'refundDetails.stripeRefundId': refund.id
  });
  
  if (!transaction) {
    return;
  }
  
  // Update refund status
  if (transaction.refundDetails) {
    transaction.refundDetails.status = refund.status;
    await transaction.save();
  }
  
  // Log the update
  await logWebhookEvent(
    'refund_status_updated',
    `Refund status updated for transaction ${transaction.transactionId}`,
    transaction.fromAccount || transaction.toAccount,
    'medium',
    req,
    {
      refundId: refund.id,
      status: refund.status,
      transactionId: transaction.transactionId
    }
  );
}

/**
 * Handle payment intent created event
 */
async function handlePaymentIntentCreated(paymentIntent, req) {
  // This is mostly informational - we may not have a transaction record yet
  await logWebhookEvent(
    'payment_intent_created',
    `Payment intent created: ${paymentIntent.id}`,
    null,
    'low',
    req,
    {
      paymentIntentId: paymentIntent.id,
      amount: paymentIntent.amount / 100,
      currency: paymentIntent.currency,
      paymentMethod: paymentIntent.payment_method_types?.[0] || 'unknown'
    }
  );
}

/**
 * Handle payment intent canceled event
 */
async function handlePaymentIntentCanceled(paymentIntent, req) {
  // Find the associated transaction
  const transaction = await Transaction.findOne({
    stripePaymentIntentId: paymentIntent.id
  });
  
  if (!transaction) {
    return;
  }
  
  // Update transaction status
  transaction.status = 'cancelled';
  transaction.statusHistory.push({
    status: 'cancelled',
    timestamp: new Date(),
    reason: paymentIntent.cancellation_reason || 'Canceled in Stripe'
  });
  
  await transaction.save();
  
  // Log the cancellation
  const auditLog = new AuditLog({
    eventType: 'transaction_cancelled',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Transaction ${transaction.transactionId} cancelled via Stripe`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    metadata: {
      stripeEvent: 'payment_intent.canceled',
      paymentIntentId: paymentIntent.id,
      reason: paymentIntent.cancellation_reason || 'Unknown'
    },
    success: true
  });
  
  await auditLog.save();
}

/**
 * Handle payment method attached event
 */
async function handlePaymentMethodAttached(paymentMethod, req) {
  // Typically this would update a stored payment method in user account
  // For audit purposes, we'll just log it
  await logWebhookEvent(
    'payment_method_attached',
    `Payment method attached: ${paymentMethod.id}`,
    paymentMethod.customer ? await findUserByStripeCustomerId(paymentMethod.customer) : null,
    'medium',
    req,
    {
      paymentMethodId: paymentMethod.id,
      type: paymentMethod.type,
      customerId: paymentMethod.customer,
      last4: paymentMethod.card?.last4 || 'N/A'
    }
  );
}

/**
 * Handle payment method detached event
 */
async function handlePaymentMethodDetached(paymentMethod, req) {
  // Similar to attached, this would update stored payment methods
  await logWebhookEvent(
    'payment_method_detached',
    `Payment method detached: ${paymentMethod.id}`,
    null,
    'medium',
    req,
    {
      paymentMethodId: paymentMethod.id,
      type: paymentMethod.type
    }
  );
}

/**
 * Handle dispute closed event
 */
async function handleDisputeClosed(dispute, req) {
  // Find the transaction with this dispute
  const transaction = await Transaction.findOne({
    stripeDisputeId: dispute.id
  });
  
  if (!transaction) {
    return;
  }
  
  // Update dispute details and transaction status
  if (transaction.disputeDetails) {
    transaction.disputeDetails.status = dispute.status;
    transaction.disputeDetails.outcome = dispute.status === 'won' ? 'won' : 'lost';
    transaction.disputeDetails.resolvedAt = new Date();
  }
  
  // If dispute was lost, mark transaction as refunded
  if (dispute.status === 'lost') {
    transaction.status = 'refunded';
    transaction.statusHistory.push({
      status: 'refunded',
      timestamp: new Date(),
      reason: 'Dispute lost'
    });
  } else if (dispute.status === 'won') {
    // If dispute was won, revert back to completed
    transaction.status = 'completed';
    transaction.statusHistory.push({
      status: 'completed',
      timestamp: new Date(),
      reason: 'Dispute won'
    });
  }
  
  await transaction.save();
  
  // Log the dispute resolution
  const auditLog = new AuditLog({
    eventType: 'dispute_closed',
    userId: transaction.fromAccount || transaction.toAccount,
    action: `Dispute closed for transaction ${transaction.transactionId}`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    riskLevel: dispute.status === 'lost' ? 'high' : 'medium',
    metadata: {
      stripeEvent: 'charge.dispute.closed',
      disputeId: dispute.id,
      status: dispute.status,
      outcome: dispute.status === 'won' ? 'won' : 'lost'
    },
    success: dispute.status === 'won'
  });
  
  await auditLog.save();
}

/**
 * Handle dispute updated event
 */
async function handleDisputeUpdated(dispute, req) {
  // Find the transaction with this dispute
  const transaction = await Transaction.findOne({
    stripeDisputeId: dispute.id
  });
  
  if (!transaction) {
    return;
  }
  
  // Update dispute details
  if (transaction.disputeDetails) {
    transaction.disputeDetails.status = dispute.status;
    transaction.disputeDetails.evidence = dispute.evidence ? 'Submitted' : 'None';
  }
  
  await transaction.save();
  
  // Log the update
  await logWebhookEvent(
    'dispute_updated',
    `Dispute updated for transaction ${transaction.transactionId}`,
    transaction.fromAccount || transaction.toAccount,
    'medium',
    req,
    {
      disputeId: dispute.id,
      status: dispute.status,
      evidenceSubmitted: !!dispute.evidence
    }
  );
}

/**
 * Utility function to find user by Stripe customer ID
 */
async function findUserByStripeCustomerId(customerId) {
  const user = await User.findOne({ stripeCustomerId: customerId });
  return user ? user._id : null;
}

module.exports = router;
