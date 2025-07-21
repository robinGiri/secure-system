const mongoose = require('mongoose');
const crypto = require('crypto');

const transactionSchema = new mongoose.Schema({
  // Transaction Identification
  transactionId: {
    type: String,
    unique: true,
    required: false // Auto-generated in pre-save hook
  },
  
  // Transaction Details
  type: {
    type: String,
    enum: ['transfer', 'deposit', 'withdrawal', 'payment'],
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: 0.01,
    validate: {
      validator: function(v) {
        return Number.isFinite(v) && v > 0;
      },
      message: 'Amount must be a positive number'
    }
  },
  currency: {
    type: String,
    default: 'USD',
    enum: ['USD', 'EUR', 'GBP', 'CAD']
  },
  description: {
    type: String,
    maxlength: 255
  },
  
  // Account Information
  fromAccount: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return ['transfer', 'withdrawal', 'payment'].includes(this.type);
    }
  },
  toAccount: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return ['transfer', 'deposit'].includes(this.type);
    }
  },
  
  // External Account Details (for external transfers)
  externalAccount: {
    bankName: String,
    accountNumber: {
      type: String,
      validate: {
        validator: function(v) {
          if (!v) return true; // Optional field
          return /^[0-9]{8,20}$/.test(v);
        },
        message: 'Account number must be 8-20 digits'
      }
    },
    routingNumber: {
      type: String,
      validate: {
        validator: function(v) {
          if (!v) return true; // Optional field
          return /^[0-9]{9}$/.test(v);
        },
        message: 'Routing number must be 9 digits'
      }
    },
    accountHolderName: String
  },
  
  // Transaction Status
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  statusHistory: [{
    status: {
      type: String,
      enum: ['pending', 'processing', 'completed', 'failed', 'cancelled']
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    reason: String,
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  
  // Security and Validation
  authenticationMethod: {
    type: String,
    enum: ['password', 'mfa', 'biometric'],
    required: true
  },
  ipAddress: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(v) || ipv6Regex.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  userAgent: String,
  
  // Risk Assessment
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  riskFactors: [{
    factor: String,
    score: Number,
    description: String
  }],
  fraudCheckStatus: {
    type: String,
    enum: ['passed', 'failed', 'manual_review'],
    default: 'passed'
  },
  
  // Balances (for audit trail)
  balanceBefore: {
    fromAccount: Number,
    toAccount: Number
  },
  balanceAfter: {
    fromAccount: Number,
    toAccount: Number
  },
  
  // Fees and Charges
  fees: [{
    type: {
      type: String,
      enum: ['processing', 'international', 'overdraft', 'service']
    },
    amount: Number,
    description: String
  }],
  totalFees: {
    type: Number,
    default: 0
  },
  
  // Processing Information
  processedAt: Date,
  processedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  processingTime: Number, // in milliseconds
  
  // External References
  externalTransactionId: String,
  paymentGatewayReference: String,
  
  // Encryption and Security
  encryptedData: String, // For sensitive information
  checksum: String, // For data integrity
  
  // Audit Trail
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

// Indexes for performance and querying
transactionSchema.index({ transactionId: 1 });
transactionSchema.index({ fromAccount: 1, createdAt: -1 });
transactionSchema.index({ toAccount: 1, createdAt: -1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ createdAt: -1 });
transactionSchema.index({ amount: 1 });

// Generate unique transaction ID
transactionSchema.pre('save', function(next) {
  if (!this.transactionId) {
    const timestamp = Date.now().toString();
    const random = Math.random().toString(36).substr(2, 9).toUpperCase();
    this.transactionId = `TXN${timestamp}${random}`;
  }
  next();
});

// Calculate total fees
transactionSchema.pre('save', function(next) {
  this.totalFees = this.fees.reduce((total, fee) => total + fee.amount, 0);
  next();
});

// Add status to history when status changes
transactionSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    this.statusHistory.push({
      status: this.status,
      timestamp: new Date(),
      updatedBy: this.processedBy
    });
  }
  next();
});

// Calculate risk score based on various factors
transactionSchema.methods.calculateRiskScore = function() {
  let score = 0;
  const factors = [];
  
  // Amount-based risk
  if (this.amount > 10000) {
    score += 30;
    factors.push({ factor: 'high_amount', score: 30, description: 'Transaction amount exceeds $10,000' });
  } else if (this.amount > 5000) {
    score += 15;
    factors.push({ factor: 'medium_amount', score: 15, description: 'Transaction amount exceeds $5,000' });
  }
  
  // Transaction type risk
  if (this.type === 'transfer' && this.externalAccount) {
    score += 20;
    factors.push({ factor: 'external_transfer', score: 20, description: 'External bank transfer' });
  }
  
  // Time-based risk (transactions outside business hours)
  const hour = new Date().getHours();
  if (hour < 6 || hour > 22) {
    score += 10;
    factors.push({ factor: 'off_hours', score: 10, description: 'Transaction outside business hours' });
  }
  
  // International transaction risk
  if (this.currency !== 'USD') {
    score += 15;
    factors.push({ factor: 'foreign_currency', score: 15, description: 'Non-USD currency transaction' });
  }
  
  this.riskScore = Math.min(score, 100);
  this.riskFactors = factors;
  
  return this.riskScore;
};

// Generate checksum for data integrity
transactionSchema.methods.generateChecksum = function() {
  const data = `${this.transactionId}${this.type}${this.amount}${this.fromAccount}${this.toAccount}${this.createdAt}`;
  this.checksum = crypto.createHash('sha256').update(data).digest('hex');
  return this.checksum;
};

// Validate checksum
transactionSchema.methods.validateChecksum = function() {
  const data = `${this.transactionId}${this.type}${this.amount}${this.fromAccount}${this.toAccount}${this.createdAt}`;
  const expectedChecksum = crypto.createHash('sha256').update(data).digest('hex');
  return this.checksum === expectedChecksum;
};

// Encrypt sensitive data
transactionSchema.methods.encryptSensitiveData = function(data) {
  const algorithm = 'aes-256-cbc';
  const key = process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key-12';
  const iv = crypto.randomBytes(16);
  
  const cipher = crypto.createCipher(algorithm, key);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  this.encryptedData = iv.toString('hex') + ':' + encrypted;
};

// Decrypt sensitive data
transactionSchema.methods.decryptSensitiveData = function() {
  if (!this.encryptedData) return null;
  
  const algorithm = 'aes-256-cbc';
  const key = process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key-12';
  const textParts = this.encryptedData.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = textParts.join(':');
  
  const decipher = crypto.createDecipher(algorithm, key);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return JSON.parse(decrypted);
};

// Static method to get transaction summary
transactionSchema.statics.getTransactionSummary = function(userId, startDate, endDate) {
  return this.aggregate([
    {
      $match: {
        $or: [{ fromAccount: userId }, { toAccount: userId }],
        createdAt: { $gte: startDate, $lte: endDate },
        status: 'completed'
      }
    },
    {
      $group: {
        _id: '$type',
        totalAmount: { $sum: '$amount' },
        count: { $sum: 1 },
        avgAmount: { $avg: '$amount' }
      }
    }
  ]);
};

// Virtual for net amount (considering fees)
transactionSchema.virtual('netAmount').get(function() {
  return this.amount + this.totalFees;
});

module.exports = mongoose.model('Transaction', transactionSchema);
