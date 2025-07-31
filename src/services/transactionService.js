/**
 * Transaction Service
 * Handles secure transaction processing with encryption and Stripe integration
 */
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');

// Initialize Stripe only if the key is provided
let stripe = null;
if (process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY !== 'sk_test_your_stripe_secret_key_here') {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

/**
 * Service for securely processing transactions
 */
class TransactionService {
  /**
   * Create and process a transaction securely with enhanced fraud detection
   * @param {Object} transactionData - Transaction data
   * @param {Object} user - User initiating the transaction
   * @param {Object} req - Request object for logging
   * @returns {Promise<Object>} Processed transaction
   */
  static async processTransaction(transactionData, user, req) {
    // Import transaction security utilities
    const { verifySafeTransaction } = require('../utils/transactionSecurity');
    const { 
      type, 
      amount, 
      currency = 'USD', 
      description, 
      toAccountNumber,
      externalAccount,
      authenticationMethod,
      paymentMethodId
    } = transactionData;
    
    // Generate an idempotency key to prevent duplicate transactions
    const idempotencyKey = uuidv4();
    
    // Validate transaction permissions and limits
    await this.validateTransactionLimits(user, type, amount);
    
    // Create a preliminary transaction object for security analysis
    const prelimTransaction = {
      type,
      amount,
      currency,
      fromAccount: user._id,
      toAccountNumber,
      externalAccount
    };
    
    // Verify transaction safety with enhanced fraud detection
    const securityVerification = await verifySafeTransaction(prelimTransaction, user, req);
    
    // Block high-risk transactions
    if (!securityVerification.allowed) {
      throw new Error('Transaction blocked due to security concerns. Please contact customer support.');
    }
    
    // Start secure processing
    let stripePaymentIntent = null;
    let stripeTransferId = null;
    let receivingUser = null;
    
    // Handle different transaction types with secure processing
    switch(type) {
      case 'deposit':
        // Create a payment intent with Stripe for deposit
        stripePaymentIntent = await this.createStripePaymentIntent(
          amount, 
          currency, 
          description, 
          user, 
          idempotencyKey,
          paymentMethodId
        );
        break;
        
      case 'transfer':
        // Handle internal transfer between accounts
        receivingUser = await User.findOne({ accountNumber: toAccountNumber });
        if (!receivingUser) {
          throw new Error('Recipient account not found');
        }
        
        // For larger transfers, create a Stripe transfer for compliance and tracking
        if (amount >= 1000) {
          stripeTransferId = await this.createStripeTransfer(
            amount, 
            currency, 
            description, 
            user, 
            receivingUser,
            idempotencyKey
          );
        }
        break;
        
      case 'withdrawal':
        // Process withdrawal through Stripe payout system
        if (amount > 0) {
          await this.createStripePayout(
            amount, 
            currency, 
            description, 
            user, 
            externalAccount,
            idempotencyKey
          );
        }
        break;
        
      case 'payment':
        // Process payment through Stripe
        stripePaymentIntent = await this.createStripePayment(
          amount, 
          currency, 
          description, 
          user, 
          externalAccount,
          idempotencyKey,
          paymentMethodId
        );
        break;
        
      default:
        throw new Error('Invalid transaction type');
    }
    
    // Create transaction record with encrypted data
    const transaction = await this.createTransactionRecord(
      transactionData,
      user,
      receivingUser,
      req,
      stripePaymentIntent,
      stripeTransferId,
      securityVerification
    );
    
    // Log transaction securely
    await this.logSecureTransaction(transaction, user, req);
    
    return transaction;
  }
  
  /**
   * Create a Stripe payment intent for processing deposits
   * @private
   */
  static async createStripePaymentIntent(amount, currency, description, user, idempotencyKey, paymentMethodId) {
    try {
      // Convert amount to cents for Stripe
      const amountInCents = Math.round(amount * 100);
      
      const paymentIntentParams = {
        amount: amountInCents,
        currency,
        description: `Deposit: ${description || 'Bank deposit'}`,
        metadata: {
          userId: user._id.toString(),
          accountNumber: user.accountNumber,
          transactionType: 'deposit',
          email: user.email
        },
        receipt_email: user.email,
        statement_descriptor: 'ROBIN BANK DEPOSIT'
      };
      
      // If a payment method is provided, attach it
      if (paymentMethodId) {
        paymentIntentParams.payment_method = paymentMethodId;
        paymentIntentParams.confirm = true;
      }
      
      const paymentIntent = await stripe.paymentIntents.create(
        paymentIntentParams,
        { idempotencyKey }
      );
      
      return paymentIntent;
    } catch (error) {
      console.error('Stripe payment intent creation failed:', error);
      throw new Error(`Payment processing failed: ${error.message}`);
    }
  }
  
  /**
   * Create a Stripe transfer for internal transfers
   * @private
   */
  static async createStripeTransfer(amount, currency, description, fromUser, toUser, idempotencyKey) {
    // This is a placeholder - in a real implementation, you would need to:
    // 1. Create Stripe Connect accounts for users
    // 2. Use Stripe Transfer API to move funds between connected accounts
    
    // For now, we'll simulate this with a record
    return `tr_${uuidv4().replace(/-/g, '')}`;
  }
  
  /**
   * Create a Stripe payout for withdrawals
   * @private
   */
  static async createStripePayout(amount, currency, description, user, externalAccount, idempotencyKey) {
    // This is a placeholder - in a real implementation, you would:
    // 1. Verify the user's Stripe Connect account
    // 2. Create a payout to their bank account
    
    // For now, we'll simulate this
    return `po_${uuidv4().replace(/-/g, '')}`;
  }
  
  /**
   * Create a Stripe payment for external payments
   * @private
   */
  static async createStripePayment(amount, currency, description, user, externalAccount, idempotencyKey, paymentMethodId) {
    try {
      // Convert amount to cents for Stripe
      const amountInCents = Math.round(amount * 100);
      
      const paymentIntentParams = {
        amount: amountInCents,
        currency,
        description: `Payment: ${description || 'Bank payment'}`,
        metadata: {
          userId: user._id.toString(),
          accountNumber: user.accountNumber,
          transactionType: 'payment',
          email: user.email,
          recipient: externalAccount?.accountHolderName
        },
        receipt_email: user.email,
        statement_descriptor: 'ROBIN BANK PAYMENT'
      };
      
      if (paymentMethodId) {
        paymentIntentParams.payment_method = paymentMethodId;
        paymentIntentParams.confirm = true;
      }
      
      const paymentIntent = await stripe.paymentIntents.create(
        paymentIntentParams,
        { idempotencyKey }
      );
      
      return paymentIntent;
    } catch (error) {
      console.error('Stripe payment creation failed:', error);
      throw new Error(`Payment processing failed: ${error.message}`);
    }
  }
  
  /**
   * Validate transaction limits and permissions
   * @private
   */
  static async validateTransactionLimits(user, type, amount) {
    // Check user account status
    if (!user.isActive) {
      throw new Error('Account is inactive');
    }
    
    // Check balance for withdrawals and transfers
    if (['withdrawal', 'transfer', 'payment'].includes(type)) {
      if (user.balance < amount) {
        throw new Error('Insufficient funds');
      }
    }
    
    // Check transaction limits based on account type
    const dailyLimit = this.getDailyTransactionLimit(user);
    
    // Get transactions in the last 24 hours
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentTransactions = await Transaction.find({
      fromAccount: user._id,
      type,
      createdAt: { $gte: oneDayAgo },
      status: { $in: ['completed', 'processing', 'pending'] }
    });
    
    const dailyTotal = recentTransactions.reduce((sum, tx) => sum + tx.amount, 0);
    
    if (dailyTotal + amount > dailyLimit) {
      throw new Error(`Daily ${type} limit of $${dailyLimit.toFixed(2)} exceeded`);
    }
    
    return true;
  }
  
  /**
   * Get daily transaction limit based on account type and status
   * @private
   */
  static getDailyTransactionLimit(user) {
    const baseLimits = {
      standard: 5000,
      premium: 25000,
      business: 50000
    };
    
    // Default to standard
    const accountTier = user.accountType || 'standard';
    let limit = baseLimits[accountTier] || baseLimits.standard;
    
    // Adjust limit based on account age and verification status
    if (user.isVerified) {
      limit *= 1.5; // 50% higher limit for verified accounts
    }
    
    // Account age in days
    const accountAge = (new Date() - user.createdAt) / (1000 * 60 * 60 * 24);
    if (accountAge > 90) {
      limit *= 1.2; // 20% higher limit for accounts older than 90 days
    }
    
    return limit;
  }
  
  /**
   * Create a transaction record with proper encryption
   * @private
   */
  static async createTransactionRecord(transactionData, fromUser, toUser, req, stripePaymentIntent, stripeTransferId, securityVerification = {}) {
    const { 
      type, 
      amount, 
      currency = 'USD', 
      description, 
      externalAccount,
      authenticationMethod,
      paymentMethodId
    } = transactionData;
    
    // Create transaction object with enhanced Stripe-specific fields
    const transaction = new Transaction({
      type,
      amount,
      currency,
      description,
      fromAccount: ['transfer', 'withdrawal', 'payment'].includes(type) ? fromUser._id : null,
      toAccount: type === 'transfer' ? toUser?._id : (type === 'deposit' ? fromUser._id : null),
      externalAccount: externalAccount ? {} : undefined, // Don't store plaintext external account details
      authenticationMethod,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      createdBy: fromUser._id,
      balanceBefore: {
        fromAccount: fromUser.balance,
        toAccount: toUser?.balance || 0
      },
      // Enhanced Stripe transaction references
      externalTransactionId: stripePaymentIntent?.id || stripeTransferId || null,
      paymentGatewayReference: stripePaymentIntent?.client_secret || null,
      stripePaymentIntentId: stripePaymentIntent?.id || null,
      stripeChargeId: stripePaymentIntent?.latest_charge || null,
      stripePaymentMethodId: paymentMethodId || stripePaymentIntent?.payment_method || null,
      stripeTransferId: stripeTransferId || null,
      
      // Add metadata for better transaction analysis
      metadata: {
        initiatedFrom: req.get('Origin') || 'API',
        deviceInfo: this.parseUserAgent(req.get('User-Agent')),
        ipLocation: req.ipInfo || null,
        paymentMethod: paymentMethodId ? 'saved_card' : 'new_card',
        sessionId: req.sessionID || null
      }
    });

    // Set risk information from our enhanced security verification
    transaction.riskScore = securityVerification.riskScore || 0;
    transaction.riskFactors = securityVerification.riskFactors || [];
    
    // Still calculate standard risk score as a backup
    if (!transaction.riskScore) {
      transaction.calculateRiskScore();
    }

    // Generate checksum
    transaction.generateChecksum();
    
    // Encrypt sensitive data if needed
    if (externalAccount) {
      // Use secure encryption method
      this.encryptSensitiveDataSecurely(transaction, externalAccount);
    }
    
    // Update balances (in a real application, this would be in a transaction)
    if (['transfer', 'withdrawal', 'payment'].includes(type)) {
      fromUser.balance -= amount;
      await fromUser.save();
    }

    if (type === 'transfer' && toUser) {
      toUser.balance += amount;
      await toUser.save();
    }

    if (type === 'deposit') {
      fromUser.balance += amount;
      await fromUser.save();
    }
    
    // Set balance after
    transaction.balanceAfter = {
      fromAccount: fromUser.balance,
      toAccount: toUser?.balance || 0
    };
    
    // Set initial status based on risk score, security verification and Stripe status
    if (stripePaymentIntent?.status === 'succeeded') {
      transaction.status = 'completed';
      transaction.processedAt = new Date();
    } else if (securityVerification.requiresReview || transaction.riskScore >= 70) {
      transaction.status = 'pending';
      transaction.fraudCheckStatus = 'manual_review';
    } else if (transaction.riskScore >= 40) {
      transaction.status = 'processing';
    } else {
      transaction.status = 'completed';
      transaction.processedAt = new Date();
    }

    await transaction.save();
    
    return transaction;
  }
  
  /**
   * Securely encrypt sensitive transaction data
   * @private
   */
  static encryptSensitiveDataSecurely(transaction, data) {
    const algorithm = 'aes-256-gcm'; // More secure than CBC
    const key = process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key-12345';
    const iv = crypto.randomBytes(16);
    
    try {
      // Create cipher with GCM mode for authenticated encryption
      const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
      
      // Encrypt data
      let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get auth tag for verification during decryption
      const authTag = cipher.getAuthTag();
      
      // Store all components needed for decryption
      transaction.encryptedData = JSON.stringify({
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag.toString('hex'),
        algorithm
      });
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt transaction data');
    }
  }
  
  /**
   * Decrypt sensitive transaction data
   * @param {Object} transaction - Transaction with encrypted data
   * @returns {Object} Decrypted data
   */
  static decryptSensitiveData(transaction) {
    if (!transaction.encryptedData) {
      return null;
    }
    
    try {
      const encryptionData = JSON.parse(transaction.encryptedData);
      const { iv, encryptedData, authTag, algorithm } = encryptionData;
      
      const key = process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key-12345';
      
      // Create decipher
      const decipher = crypto.createDecipheriv(
        algorithm,
        Buffer.from(key),
        Buffer.from(iv, 'hex')
      );
      
      // Set auth tag for verification
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      // Decrypt
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt transaction data');
    }
  }
  
  /**
   * Log transaction securely
   * @private
   */
  static async logSecureTransaction(transaction, user, req) {
    // Create detailed audit log for the transaction with enhanced security context
    const auditLog = new AuditLog({
      eventType: 'transaction_created',
      userId: user._id,
      username: user.username,
      userRole: user.role,
      sessionId: req.sessionID,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      action: `Created ${transaction.type} transaction for $${transaction.amount}`,
      resource: 'transaction',
      resourceId: transaction._id.toString(),
      riskLevel: transaction.riskScore >= 40 ? 'high' : 'medium',
      metadata: {
        transactionId: transaction.transactionId,
        amount: transaction.amount,
        type: transaction.type,
        externalTransactionId: transaction.externalTransactionId,
        stripePaymentIntentId: transaction.stripePaymentIntentId,
        stripeChargeId: transaction.stripeChargeId,
        stripePaymentMethodId: transaction.stripePaymentMethodId,
        riskScore: transaction.riskScore,
        riskFactors: transaction.riskFactors,
        initiatedFrom: req.get('Origin') || 'API',
        httpMethod: req.method,
        endpoint: req.originalUrl,
        referrer: req.get('Referer') || null,
        timeOfDay: new Date().toISOString(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      success: true
    });

    await auditLog.save();
    
    // For high-risk transactions, create additional security logs
    if (transaction.riskScore >= 60) {
      await this.createSecurityAlert(transaction, user, req);
    }
  }
  
  /**
   * Parse user agent for device information
   * @private
   */
  static parseUserAgent(userAgent) {
    if (!userAgent) return { type: 'unknown' };
    
    const isMobile = /mobile|android|iphone|ipad|ipod/i.test(userAgent);
    const isTablet = /tablet|ipad/i.test(userAgent);
    const isDesktop = !isMobile && !isTablet;
    
    const browserInfo = {};
    
    if (/chrome/i.test(userAgent)) browserInfo.browser = 'Chrome';
    else if (/firefox/i.test(userAgent)) browserInfo.browser = 'Firefox';
    else if (/safari/i.test(userAgent)) browserInfo.browser = 'Safari';
    else if (/edge|edg/i.test(userAgent)) browserInfo.browser = 'Edge';
    else if (/msie|trident/i.test(userAgent)) browserInfo.browser = 'Internet Explorer';
    else browserInfo.browser = 'Other';
    
    if (/windows/i.test(userAgent)) browserInfo.os = 'Windows';
    else if (/mac/i.test(userAgent)) browserInfo.os = 'MacOS';
    else if (/linux/i.test(userAgent)) browserInfo.os = 'Linux';
    else if (/android/i.test(userAgent)) browserInfo.os = 'Android';
    else if (/iphone|ipad|ipod/i.test(userAgent)) browserInfo.os = 'iOS';
    else browserInfo.os = 'Other';
    
    return {
      type: isDesktop ? 'desktop' : (isTablet ? 'tablet' : 'mobile'),
      ...browserInfo
    };
  }
  
  /**
   * Create security alert for high-risk transactions
   * @private
   */
  static async createSecurityAlert(transaction, user, req) {
    const auditLog = new AuditLog({
      eventType: 'security_alert',
      userId: user._id,
      username: user.username,
      userRole: user.role,
      sessionId: req.sessionID,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      action: `High-risk transaction detected: ${transaction.transactionId}`,
      resource: 'transaction',
      resourceId: transaction._id.toString(),
      riskLevel: 'high',
      metadata: {
        transactionId: transaction.transactionId,
        amount: transaction.amount,
        type: transaction.type,
        riskScore: transaction.riskScore,
        riskFactors: transaction.riskFactors,
        alertReason: 'High risk score',
        recommendedAction: transaction.riskScore >= 80 ? 'manual_review' : 'monitor',
        timeStamp: new Date().toISOString()
      },
      success: false
    });

    await auditLog.save();
    
    // Here you could implement additional notifications like email or SMS alerts
  }

  /**
   * Reconcile transactions with Stripe records
   * @param {Date} startDate - Start date for reconciliation
   * @param {Date} endDate - End date for reconciliation
   * @param {String} userId - User ID of the person performing reconciliation
   * @returns {Promise<Object>} Reconciliation results
   */
  static async reconcileWithStripe(startDate, endDate, userId) {
    try {
      // Get all non-reconciled transactions in the date range
      const transactions = await Transaction.find({
        createdAt: { $gte: startDate, $lte: endDate },
        isReconciled: false,
        stripePaymentIntentId: { $exists: true, $ne: null }
      });
      
      const results = {
        total: transactions.length,
        reconciled: 0,
        failed: 0,
        discrepancies: []
      };
      
      // Process each transaction
      for (const transaction of transactions) {
        try {
          // Get the corresponding Stripe payment intent
          const paymentIntent = await stripe.paymentIntents.retrieve(transaction.stripePaymentIntentId);
          
          // Compare key data points
          const stripeAmount = paymentIntent.amount / 100;
          const stripeCurrency = paymentIntent.currency.toUpperCase();
          
          // Check for discrepancies
          const discrepancies = [];
          
          if (Math.abs(stripeAmount - transaction.amount) > 0.01) {
            discrepancies.push({
              field: 'amount',
              local: transaction.amount,
              stripe: stripeAmount
            });
          }
          
          if (stripeCurrency !== transaction.currency) {
            discrepancies.push({
              field: 'currency',
              local: transaction.currency,
              stripe: stripeCurrency
            });
          }
          
          // Status reconciliation
          const stripeStatus = this.mapStripeStatusToLocal(paymentIntent.status);
          if (stripeStatus !== transaction.status) {
            discrepancies.push({
              field: 'status',
              local: transaction.status,
              stripe: stripeStatus
            });
            
            // Update local status to match Stripe
            transaction.status = stripeStatus;
            transaction.statusHistory.push({
              status: stripeStatus,
              timestamp: new Date(),
              reason: 'Status updated during reconciliation',
              updatedBy: userId
            });
          }
          
          // Mark as reconciled
          transaction.isReconciled = true;
          transaction.reconciliationDetails = {
            reconciliationId: `recon_${Date.now()}`,
            reconciledAt: new Date(),
            reconciliationMethod: 'automatic',
            reconciledBy: userId,
            notes: discrepancies.length ? 'Discrepancies found and resolved' : 'No discrepancies found'
          };
          
          // If there are discrepancies, log them
          if (discrepancies.length) {
            results.discrepancies.push({
              transactionId: transaction.transactionId,
              stripeId: transaction.stripePaymentIntentId,
              discrepancies
            });
          }
          
          // Save updated transaction
          await transaction.save();
          results.reconciled++;
        } catch (error) {
          results.failed++;
          console.error(`Reconciliation failed for transaction ${transaction.transactionId}:`, error);
        }
      }
      
      return results;
    } catch (error) {
      console.error('Transaction reconciliation failed:', error);
      throw new Error(`Reconciliation process failed: ${error.message}`);
    }
  }
  
  /**
   * Map Stripe status to local transaction status
   * @private
   */
  static mapStripeStatusToLocal(stripeStatus) {
    const statusMap = {
      'requires_payment_method': 'pending',
      'requires_confirmation': 'pending',
      'requires_action': 'processing',
      'processing': 'processing',
      'requires_capture': 'processing',
      'succeeded': 'completed',
      'canceled': 'cancelled'
    };
    
    return statusMap[stripeStatus] || 'pending';
  }

  /**
   * Handle refund through Stripe
   * @param {String} transactionId - Transaction ID to refund
   * @param {Number} amount - Amount to refund (null for full refund)
   * @param {String} reason - Reason for refund
   * @param {Object} user - User performing the refund
   * @returns {Promise<Object>} Refund result
   */
  static async processRefund(transactionId, amount, reason, user) {
    // Start a database transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Find the transaction
      const transaction = await Transaction.findOne({ transactionId });
      
      if (!transaction) {
        throw new Error('Transaction not found');
      }
      
      if (transaction.type === 'refund') {
        throw new Error('Cannot refund a refund');
      }
      
      if (!transaction.stripeChargeId && !transaction.stripePaymentIntentId) {
        throw new Error('No Stripe charge ID associated with this transaction');
      }
      
      if (!['completed', 'processing'].includes(transaction.status)) {
        throw new Error(`Cannot refund a transaction with status: ${transaction.status}`);
      }
      
      // Create refund in Stripe
      const refundParams = {
        charge: transaction.stripeChargeId,
        amount: amount ? Math.round(amount * 100) : undefined, // Convert to cents if partial refund
        reason: reason || 'requested_by_customer',
        metadata: {
          transactionId: transaction.transactionId,
          refundedBy: user._id.toString(),
          originalAmount: transaction.amount,
          refundAmount: amount || transaction.amount
        }
      };
      
      const stripeRefund = await stripe.refunds.create(refundParams);
      
      // Create a refund transaction
      const refundTransaction = new Transaction({
        type: 'refund',
        amount: amount || transaction.amount,
        currency: transaction.currency,
        description: `Refund for transaction ${transaction.transactionId}: ${reason || 'Customer request'}`,
        fromAccount: transaction.toAccount,
        toAccount: transaction.fromAccount,
        authenticationMethod: 'password',
        ipAddress: user.ip,
        userAgent: user.userAgent,
        createdBy: user._id,
        status: 'completed',
        processedAt: new Date(),
        externalTransactionId: stripeRefund.id,
        stripeRefundId: stripeRefund.id,
        stripeChargeId: transaction.stripeChargeId,
        stripePaymentIntentId: transaction.stripePaymentIntentId
      });
      
      // Calculate risk score and generate checksum
      refundTransaction.calculateRiskScore();
      refundTransaction.generateChecksum();
      
      // Update original transaction
      transaction.status = amount && amount < transaction.amount ? 'partial_refund' : 'refunded';
      transaction.statusHistory.push({
        status: transaction.status,
        timestamp: new Date(),
        reason: reason || 'Customer request',
        updatedBy: user._id
      });
      
      transaction.refundDetails = {
        stripeRefundId: stripeRefund.id,
        reason: reason || 'Customer request',
        amount: amount || transaction.amount,
        currency: transaction.currency,
        createdAt: new Date(),
        status: stripeRefund.status
      };
      
      // Save both transactions
      await refundTransaction.save({ session });
      await transaction.save({ session });
      
      // Commit the transaction
      await session.commitTransaction();
      
      return {
        success: true,
        refundTransactionId: refundTransaction.transactionId,
        stripeRefundId: stripeRefund.id,
        amount: amount || transaction.amount,
        status: stripeRefund.status
      };
    } catch (error) {
      // Abort the transaction on error
      await session.abortTransaction();
      console.error('Refund processing failed:', error);
      throw new Error(`Refund failed: ${error.message}`);
    } finally {
      // End the session
      session.endSession();
    }
  }
}

module.exports = TransactionService;
