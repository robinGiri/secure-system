/**
 * Transaction Security Utilities
 * Functions for detecting and preventing fraudulent transactions
 */
const AuditLog = require('../models/AuditLog');

/**
 * Check for suspicious patterns in a transaction
 * @param {Object} transaction - Transaction object to analyze
 * @param {Object} user - User initiating the transaction
 * @param {Object} req - Request object for contextual info
 * @returns {Object} - Analysis result with risk factors
 */
async function detectSuspiciousTransaction(transaction, user, req) {
  const riskFactors = [];
  let riskScore = 0;
  
  // Check for recent failed transactions
  const recentFailedCount = await checkRecentFailedTransactions(user._id);
  if (recentFailedCount > 2) {
    riskFactors.push({
      type: 'recent_failures',
      description: `User has ${recentFailedCount} recent failed transactions`,
      score: recentFailedCount * 5,
      severity: recentFailedCount > 5 ? 'high' : 'medium'
    });
    riskScore += recentFailedCount * 5;
  }
  
  // Check for unusual transaction amount
  if (transaction.amount > user.highestTransaction * 2 && transaction.amount > 1000) {
    const amountRiskFactor = {
      type: 'unusual_amount',
      description: 'Transaction amount significantly higher than user history',
      score: 20,
      severity: 'medium'
    };
    riskFactors.push(amountRiskFactor);
    riskScore += 20;
  }
  
  // Check for unusual location/IP
  if (user.lastLoginIp && req.ip !== user.lastLoginIp) {
    // In a real system, you would use geolocation data to calculate distance
    const ipRiskFactor = {
      type: 'ip_change',
      description: 'Transaction initiated from different IP than last login',
      score: 15,
      severity: 'medium'
    };
    riskFactors.push(ipRiskFactor);
    riskScore += 15;
  }
  
  // Check for unusual timing
  const hour = new Date().getHours();
  if (hour < 6 || hour > 22) {
    const timeRiskFactor = {
      type: 'unusual_time',
      description: 'Transaction outside normal business hours',
      score: 10,
      severity: 'low'
    };
    riskFactors.push(timeRiskFactor);
    riskScore += 10;
  }
  
  // Check for rapid successive transactions
  const recentTransactionCount = await checkRecentTransactions(user._id);
  if (recentTransactionCount > 5) { // More than 5 transactions in the last hour
    const frequencyRiskFactor = {
      type: 'high_frequency',
      description: `${recentTransactionCount} transactions in the past hour`,
      score: Math.min(recentTransactionCount * 3, 30),
      severity: recentTransactionCount > 10 ? 'high' : 'medium'
    };
    riskFactors.push(frequencyRiskFactor);
    riskScore += Math.min(recentTransactionCount * 3, 30);
  }
  
  // Check for new payee (for transfers)
  if (transaction.type === 'transfer' && transaction.toAccount) {
    const isNewPayee = await isFirstTimePayee(user._id, transaction.toAccount);
    if (isNewPayee) {
      const newPayeeRiskFactor = {
        type: 'new_recipient',
        description: 'First transfer to this recipient',
        score: 15,
        severity: 'medium'
      };
      riskFactors.push(newPayeeRiskFactor);
      riskScore += 15;
    }
  }
  
  // Check for international transaction
  if (transaction.currency !== 'USD') {
    const currencyRiskFactor = {
      type: 'international',
      description: 'International transaction',
      score: 10,
      severity: 'low'
    };
    riskFactors.push(currencyRiskFactor);
    riskScore += 10;
  }
  
  // Determine overall risk level
  let riskLevel;
  if (riskScore >= 50) riskLevel = 'high';
  else if (riskScore >= 25) riskLevel = 'medium';
  else riskLevel = 'low';
  
  return {
    isHighRisk: riskScore >= 50,
    requiresReview: riskScore >= 70,
    blockTransaction: riskScore >= 90,
    riskScore,
    riskLevel,
    riskFactors,
  };
}

/**
 * Check for recent failed transactions
 * @private
 */
async function checkRecentFailedTransactions(userId) {
  const Transaction = require('../models/Transaction');
  
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  
  const count = await Transaction.countDocuments({
    fromAccount: userId,
    status: 'failed',
    createdAt: { $gte: oneHourAgo }
  });
  
  return count;
}

/**
 * Check for recent transactions (any status)
 * @private
 */
async function checkRecentTransactions(userId) {
  const Transaction = require('../models/Transaction');
  
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  
  const count = await Transaction.countDocuments({
    fromAccount: userId,
    createdAt: { $gte: oneHourAgo }
  });
  
  return count;
}

/**
 * Check if this is the first transfer to this recipient
 * @private
 */
async function isFirstTimePayee(fromUserId, toUserId) {
  const Transaction = require('../models/Transaction');
  
  const previousTransfers = await Transaction.countDocuments({
    fromAccount: fromUserId,
    toAccount: toUserId,
    type: 'transfer',
    status: 'completed'
  });
  
  return previousTransfers === 0;
}

/**
 * Log security event for suspicious transaction
 * @param {Object} transaction - The transaction object
 * @param {Object} securityAnalysis - Results of security analysis
 * @param {Object} req - Request object
 */
async function logSuspiciousTransaction(transaction, securityAnalysis, req) {
  const auditLog = new AuditLog({
    eventType: 'suspicious_transaction',
    userId: transaction.fromAccount,
    action: `Suspicious transaction detected: ${transaction.transactionId}`,
    resource: 'transaction',
    resourceId: transaction._id.toString(),
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    riskLevel: securityAnalysis.riskLevel,
    metadata: {
      transactionId: transaction.transactionId,
      type: transaction.type,
      amount: transaction.amount,
      currency: transaction.currency,
      riskScore: securityAnalysis.riskScore,
      riskFactors: securityAnalysis.riskFactors,
      requiresReview: securityAnalysis.requiresReview,
      blockTransaction: securityAnalysis.blockTransaction
    },
    success: false
  });

  await auditLog.save();
  
  // If transaction is very high risk, could trigger additional alerts here
  if (securityAnalysis.blockTransaction) {
    // In a real system, you could trigger fraud alerts, SMS notifications, etc.
    console.error(`BLOCKED HIGH-RISK TRANSACTION: ${transaction.transactionId}`);
  }
}

/**
 * Verify if a transaction should be allowed to proceed
 * @param {Object} transaction - The transaction to verify
 * @param {Object} user - The user initiating the transaction
 * @param {Object} req - The request object
 * @returns {Object} - Decision and risk information
 */
async function verifySafeTransaction(transaction, user, req) {
  // Analyze the transaction for suspicious patterns
  const securityAnalysis = await detectSuspiciousTransaction(transaction, user, req);
  
  // Log suspicious transactions
  if (securityAnalysis.isHighRisk) {
    await logSuspiciousTransaction(transaction, securityAnalysis, req);
  }
  
  // Return verification result
  return {
    allowed: !securityAnalysis.blockTransaction,
    requiresReview: securityAnalysis.requiresReview,
    riskScore: securityAnalysis.riskScore,
    riskFactors: securityAnalysis.riskFactors,
    riskLevel: securityAnalysis.riskLevel
  };
}

module.exports = {
  verifySafeTransaction,
  detectSuspiciousTransaction,
  logSuspiciousTransaction
};
