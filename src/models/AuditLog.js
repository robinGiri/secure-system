const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  // Event Information
  eventType: {
    type: String,
    required: true,
    enum: [
      'user_login',
      'user_logout',
      'login_failed',
      'password_change',
      'password_reset',
      'mfa_enabled',
      'mfa_disabled',
      'mfa_verified',
      'account_locked',
      'account_unlocked',
      'profile_updated',
      'transaction_created',
      'transaction_updated',
      'transaction_deleted',
      'admin_action',
      'permission_changed',
      'session_created',
      'session_destroyed',
      'suspicious_activity',
      'data_access',
      'data_modification',
      'system_error',
      'security_violation'
    ]
  },
  
  // User Information
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return this.eventType !== 'system_error';
    }
  },
  username: String,
  userRole: String,
  
  // Session Information
  sessionId: String,
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: String,
  
  // Request Information
  method: String, // HTTP method
  url: String,
  endpoint: String,
  requestId: String,
  
  // Event Details
  action: {
    type: String,
    required: true
  },
  resource: String, // What was accessed/modified
  resourceId: String,
  oldValues: mongoose.Schema.Types.Mixed,
  newValues: mongoose.Schema.Types.Mixed,
  
  // Result Information
  success: {
    type: Boolean,
    default: true
  },
  statusCode: Number,
  errorMessage: String,
  errorCode: String,
  
  // Security Context
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  securityFlags: [{
    flag: String,
    reason: String
  }],
  
  // Additional Context
  metadata: mongoose.Schema.Types.Mixed,
  duration: Number, // Request duration in milliseconds
  
  // Geolocation
  location: {
    country: String,
    region: String,
    city: String,
    latitude: Number,
    longitude: Number
  },
  
  // Timestamps
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  },
  
  // Data Integrity
  checksum: String
}, {
  timestamps: false // We use our own timestamp field
});

// Indexes for efficient querying
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ eventType: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });
auditLogSchema.index({ success: 1, timestamp: -1 });
auditLogSchema.index({ riskLevel: 1, timestamp: -1 });
auditLogSchema.index({ sessionId: 1 });

// Generate checksum before saving
auditLogSchema.pre('save', function(next) {
  const crypto = require('crypto');
  const data = `${this.eventType}${this.userId}${this.action}${this.timestamp}${this.ipAddress}`;
  this.checksum = crypto.createHash('sha256').update(data).digest('hex');
  next();
});

// Static methods for common queries
auditLogSchema.statics.getSecurityEvents = function(timeRange = 24) {
  const since = new Date(Date.now() - timeRange * 60 * 60 * 1000);
  return this.find({
    timestamp: { $gte: since },
    eventType: { 
      $in: [
        'login_failed',
        'account_locked',
        'suspicious_activity',
        'security_violation',
        'mfa_disabled'
      ]
    }
  }).sort({ timestamp: -1 });
};

auditLogSchema.statics.getUserActivity = function(userId, limit = 50) {
  return this.find({ userId })
    .sort({ timestamp: -1 })
    .limit(limit)
    .populate('userId', 'username email');
};

auditLogSchema.statics.getFailedLogins = function(timeRange = 1) {
  const since = new Date(Date.now() - timeRange * 60 * 60 * 1000);
  return this.aggregate([
    {
      $match: {
        eventType: 'login_failed',
        timestamp: { $gte: since }
      }
    },
    {
      $group: {
        _id: '$ipAddress',
        attempts: { $sum: 1 },
        lastAttempt: { $max: '$timestamp' },
        usernames: { $addToSet: '$username' }
      }
    },
    {
      $match: {
        attempts: { $gte: 3 }
      }
    },
    {
      $sort: { attempts: -1 }
    }
  ]);
};

auditLogSchema.statics.getSuspiciousActivity = function(timeRange = 24) {
  const since = new Date(Date.now() - timeRange * 60 * 60 * 1000);
  
  return this.aggregate([
    {
      $match: {
        timestamp: { $gte: since },
        $or: [
          { riskLevel: { $in: ['high', 'critical'] } },
          { eventType: 'suspicious_activity' },
          { 'securityFlags.0': { $exists: true } }
        ]
      }
    },
    {
      $group: {
        _id: {
          userId: '$userId',
          ipAddress: '$ipAddress'
        },
        events: { $sum: 1 },
        riskEvents: {
          $sum: {
            $cond: [
              { $in: ['$riskLevel', ['high', 'critical']] },
              1,
              0
            ]
          }
        },
        lastActivity: { $max: '$timestamp' },
        eventTypes: { $addToSet: '$eventType' }
      }
    },
    {
      $match: {
        $or: [
          { events: { $gte: 10 } },
          { riskEvents: { $gte: 3 } }
        ]
      }
    },
    {
      $sort: { riskEvents: -1, events: -1 }
    }
  ]);
};

auditLogSchema.statics.getSystemHealth = function(timeRange = 1) {
  const since = new Date(Date.now() - timeRange * 60 * 60 * 1000);
  
  return this.aggregate([
    {
      $match: {
        timestamp: { $gte: since }
      }
    },
    {
      $group: {
        _id: null,
        totalEvents: { $sum: 1 },
        successfulEvents: {
          $sum: { $cond: ['$success', 1, 0] }
        },
        errorEvents: {
          $sum: { $cond: ['$success', 0, 1] }
        },
        securityEvents: {
          $sum: {
            $cond: [
              {
                $in: ['$eventType', [
                  'login_failed',
                  'suspicious_activity',
                  'security_violation'
                ]]
              },
              1,
              0
            ]
          }
        },
        avgDuration: { $avg: '$duration' }
      }
    },
    {
      $project: {
        _id: 0,
        totalEvents: 1,
        successRate: {
          $multiply: [
            { $divide: ['$successfulEvents', '$totalEvents'] },
            100
          ]
        },
        errorRate: {
          $multiply: [
            { $divide: ['$errorEvents', '$totalEvents'] },
            100
          ]
        },
        securityIncidents: '$securityEvents',
        avgResponseTime: '$avgDuration'
      }
    }
  ]);
};

// Instance methods
auditLogSchema.methods.markAsReviewed = function(reviewedBy) {
  this.metadata = this.metadata || {};
  this.metadata.reviewedBy = reviewedBy;
  this.metadata.reviewedAt = new Date();
  return this.save();
};

auditLogSchema.methods.addSecurityFlag = function(flag, reason) {
  this.securityFlags.push({ flag, reason });
  if (this.riskLevel === 'low') {
    this.riskLevel = 'medium';
  }
  return this.save();
};

// Virtual for formatted timestamp
auditLogSchema.virtual('formattedTimestamp').get(function() {
  return this.timestamp.toISOString();
});

// Virtual for event summary
auditLogSchema.virtual('summary').get(function() {
  return `${this.eventType}: ${this.action} by ${this.username || 'system'} from ${this.ipAddress}`;
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
