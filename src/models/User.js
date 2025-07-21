const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  // Basic Information
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
    match: /^[a-zA-Z0-9_]+$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  
  // Authentication
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  passwordHistory: [{
    password: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  passwordLastChanged: {
    type: Date,
    default: Date.now
  },
  passwordExpiresAt: {
    type: Date,
    default: function() {
      const expiryDays = parseInt(process.env.PASSWORD_EXPIRY_DAYS) || 90;
      return new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
    }
  },
  
  // Role-Based Access Control
  role: {
    type: String,
    enum: ['user', 'admin', 'manager', 'viewer'],
    default: 'user'
  },
  permissions: [{
    resource: String,
    actions: [String] // ['read', 'write', 'delete', 'update']
  }],
  
  // Multi-Factor Authentication
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  mfaSecret: {
    type: String,
    select: false // Don't include in regular queries
  },
  mfaBackupCodes: [{
    code: String,
    used: {
      type: Boolean,
      default: false
    }
  }],
  
  // Account Security
  isActive: {
    type: Boolean,
    default: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationTokenExpires: Date,
  
  // Password Reset
  passwordResetToken: String,
  passwordResetExpires: Date,
  
  // Login Attempts and Lockout
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  
  // Session Management
  activeSessions: [{
    sessionId: String,
    ipAddress: String,
    userAgent: String,
    createdAt: {
      type: Date,
      default: Date.now
    },
    lastActivity: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Profile Information
  profilePicture: String,
  phoneNumber: {
    type: String,
    match: /^\+?[\d\s\-\(\)]+$/
  },
  dateOfBirth: Date,
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  
  // Banking Specific (for this application)
  accountNumber: {
    type: String,
    unique: true,
    sparse: true
  },
  balance: {
    type: Number,
    default: 0,
    min: 0
  },
  accountType: {
    type: String,
    enum: ['savings', 'checking', 'business'],
    default: 'savings'
  },
  
  // Audit Trail
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date,
  lastPasswordChange: Date,
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Indexes for performance and security
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ accountNumber: 1 });
userSchema.index({ 'activeSessions.sessionId': 1 });

// Password validation
userSchema.methods.validatePassword = function(password) {
  const minLength = parseInt(process.env.MIN_PASSWORD_LENGTH) || 8;
  const maxLength = parseInt(process.env.MAX_PASSWORD_LENGTH) || 128;
  
  if (password.length < minLength || password.length > maxLength) {
    return { valid: false, message: `Password must be between ${minLength} and ${maxLength} characters` };
  }
  
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
    return { 
      valid: false, 
      message: 'Password must contain at least one uppercase letter, lowercase letter, number, and special character' 
    };
  }
  
  return { valid: true };
};

// Check password against history
userSchema.methods.isPasswordInHistory = async function(password) {
  const historyCount = parseInt(process.env.PASSWORD_HISTORY_COUNT) || 5;
  const recentPasswords = this.passwordHistory.slice(-historyCount);
  
  for (const historyEntry of recentPasswords) {
    if (await bcrypt.compare(password, historyEntry.password)) {
      return true;
    }
  }
  return false;
};

// Password hashing middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  // Validate password
  const validation = this.validatePassword(this.password);
  if (!validation.valid) {
    return next(new Error(validation.message));
  }
  
  // Check password history
  if (await this.isPasswordInHistory(this.password)) {
    return next(new Error('Cannot reuse recent passwords'));
  }
  
  // Hash password
  const salt = await bcrypt.genSalt(12);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  
  // Add current password to history before updating
  if (this.isModified('password') && !this.isNew) {
    this.passwordHistory.push({
      password: this.password,
      createdAt: new Date()
    });
    
    // Keep only recent passwords
    const historyCount = parseInt(process.env.PASSWORD_HISTORY_COUNT) || 5;
    this.passwordHistory = this.passwordHistory.slice(-historyCount);
  }
  
  this.password = hashedPassword;
  this.passwordLastChanged = new Date();
  
  // Set password expiry
  const expiryDays = parseInt(process.env.PASSWORD_EXPIRY_DAYS) || 90;
  this.passwordExpiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
  
  next();
});

// Generate account number
userSchema.pre('save', function(next) {
  if (!this.accountNumber && this.isNew) {
    this.accountNumber = 'ACC' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
  }
  next();
});

// Password comparison
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Handle login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: {
        lockUntil: 1
      },
      $set: {
        loginAttempts: 1
      }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // If we have max attempts and no lock, set lock
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: {
      loginAttempts: 1,
      lockUntil: 1
    }
  });
};

// Generate password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Generate verification token
userSchema.methods.createVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.verificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  
  this.verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verificationToken;
};

// Add session
userSchema.methods.addSession = function(sessionId, ipAddress, userAgent) {
  this.activeSessions.push({
    sessionId,
    ipAddress,
    userAgent,
    createdAt: new Date(),
    lastActivity: new Date()
  });
  
  // Keep only last 5 sessions
  this.activeSessions = this.activeSessions.slice(-5);
  
  return this.save();
};

// Remove session
userSchema.methods.removeSession = function(sessionId) {
  this.activeSessions = this.activeSessions.filter(
    session => session.sessionId !== sessionId
  );
  return this.save();
};

// Check if password is expired
userSchema.methods.isPasswordExpired = function() {
  return this.passwordExpiresAt < new Date();
};

// Get user permissions
userSchema.methods.hasPermission = function(resource, action) {
  if (this.role === 'admin') return true;
  
  const permission = this.permissions.find(p => p.resource === resource);
  return permission && permission.actions.includes(action);
};

module.exports = mongoose.model('User', userSchema);
