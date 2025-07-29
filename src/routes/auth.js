const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { 
  authenticateSession, 
  loginLimiter, 
  sensitiveOperationLimiter,
  logSecurityEvent 
} = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityIncident } = require('../middleware/auditLogger');

const router = express.Router();

// Validation rules
const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 characters and contain only letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be 8-128 characters with at least one uppercase, lowercase, number, and special character'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .trim()
    .withMessage('First name is required'),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .trim()
    .withMessage('Last name is required')
];

const loginValidation = [
  body('username')
    .notEmpty()
    .withMessage('Username or email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Register user
router.post('/register', registerValidation, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { username, email, password, firstName, lastName, phoneNumber } = req.body;

  // Check if user exists
  const existingUser = await User.findOne({
    $or: [{ email }, { username }]
  });

  if (existingUser) {
    await logSecurityEvent(req, 'user_registration', 'Registration failed - user already exists', null, false);
    return res.status(400).json({
      success: false,
      message: 'User with this email or username already exists'
    });
  }

  // Create user
  const user = new User({
    username,
    email,
    password,
    firstName,
    lastName,
    phoneNumber,
    role: 'user'
  });

  await user.save();

  // Generate verification token
  const verificationToken = user.createVerificationToken();
  await user.save();

  await logSecurityEvent(req, 'user_registration', 'User registered successfully', user._id, true);

  res.status(201).json({
    success: true,
    message: 'User registered successfully. Please verify your email.',
    data: {
      userId: user._id,
      username: user.username,
      email: user.email,
      accountNumber: user.accountNumber
    }
  });
}));

// Login user
router.post('/login', loginLimiter, loginValidation, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { username, password, mfaToken } = req.body;

  // Find user by username or email
  const user = await User.findOne({
    $or: [{ username }, { email: username }]
  }).select('+mfaSecret');

  if (!user) {
    await logSecurityEvent(req, 'login_failed', 'User not found', null, false);
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // Check password
  const passwordMatch = await user.comparePassword(password);

  if (!passwordMatch) {
    // Increment login attempts if user exists
    if (user) {
      await user.incLoginAttempts();
    }
    
    await logSecurityEvent(req, 'login_failed', 'Invalid credentials', user?._id, false);
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // Check if account is locked
  if (user.isLocked) {
    await logSecurityEvent(req, 'login_failed', 'Account locked', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Account is locked due to multiple failed login attempts. Please try again later.'
    });
  }

  // Check if account is active
  if (!user.isActive) {
    await logSecurityEvent(req, 'login_failed', 'Account inactive', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Account is deactivated. Please contact support.'
    });
  }

  // Check password expiry
  if (user.isPasswordExpired()) {
    await logSecurityEvent(req, 'login_failed', 'Password expired', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Password has expired. Please reset your password.',
      requirePasswordReset: true
    });
  }

  // MFA verification if enabled
  if (user.mfaEnabled) {
    if (!mfaToken) {
      return res.status(200).json({
        success: false,
        requireMFA: true,
        message: 'Multi-factor authentication required'
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: parseInt(process.env.MFA_WINDOW) || 2
    });

    if (!verified) {
      await user.incLoginAttempts();
      await logSecurityEvent(req, 'mfa_failed', 'MFA verification failed', user._id, false);
      return res.status(401).json({
        success: false,
        message: 'Invalid MFA token'
      });
    }

    req.session.mfaVerified = true;
    await logSecurityEvent(req, 'mfa_verified', 'MFA verification successful', user._id, true);
  }

  // Reset login attempts on successful login
  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }

  // Update last login
  user.lastLogin = new Date();
  await user.save();

  // Create session
  req.session.user = {
    id: user._id,
    username: user.username,
    role: user.role
  };

  // Add session to user's active sessions
  await user.addSession(req.sessionID, req.ip, req.get('User-Agent'));

  // Generate JWT token (optional, for API access)
  const token = jwt.sign(
    { userId: user._id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );

  await logSecurityEvent(req, 'user_login', 'User logged in successfully', user._id, true);

  const responseData = {
    success: true,
    message: 'Login successful',
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        accountNumber: user.accountNumber,
        mfaEnabled: user.mfaEnabled
      },
      token,
      sessionId: req.sessionID
    }
  };

  res.json(responseData);
}));

// Logout user
router.post('/logout', authenticateSession, asyncHandler(async (req, res) => {
  const sessionId = req.sessionID;
  const userId = req.user._id;

  // Remove session from user's active sessions
  await req.user.removeSession(sessionId);

  // Destroy session
  req.session.destroy();

  await logSecurityEvent(req, 'user_logout', 'User logged out successfully', userId, true);

  res.json({
    success: true,
    message: 'Logged out successfully'
  });
}));

// Enable MFA
router.post('/mfa/enable', authenticateSession, sensitiveOperationLimiter, asyncHandler(async (req, res) => {
  const user = req.user;

  if (user.mfaEnabled) {
    return res.status(400).json({
      success: false,
      message: 'MFA is already enabled'
    });
  }

  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `${process.env.MFA_ISSUER || 'SecureApp'}:${user.email}`,
    issuer: process.env.MFA_ISSUER || 'SecureApp',
    length: 32
  });

  // Generate QR code
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  // Save secret to user (will be confirmed when first token is verified)
  user.mfaSecret = secret.base32;
  await user.save();

  res.json({
    success: true,
    message: 'MFA setup initiated',
    data: {
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32
    }
  });
}));

// Verify and confirm MFA setup
router.post('/mfa/verify', authenticateSession, asyncHandler(async (req, res) => {
  const { token } = req.body;
  const user = req.user;

  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'MFA token is required'
    });
  }

  if (!user.mfaSecret) {
    return res.status(400).json({
      success: false,
      message: 'MFA setup not initiated'
    });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
    window: 2
  });

  if (!verified) {
    await logSecurityEvent(req, 'mfa_verification', 'MFA verification failed', user._id, false);
    return res.status(400).json({
      success: false,
      message: 'Invalid MFA token'
    });
  }

  // Enable MFA
  user.mfaEnabled = true;

  // Generate backup codes
  const backupCodes = [];
  for (let i = 0; i < 10; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    backupCodes.push(code);
    user.mfaBackupCodes.push({ code });
  }

  await user.save();

  await logSecurityEvent(req, 'mfa_enabled', 'MFA enabled successfully', user._id, true);

  res.json({
    success: true,
    message: 'MFA enabled successfully',
    data: {
      backupCodes
    }
  });
}));

// Disable MFA
router.post('/mfa/disable', authenticateSession, sensitiveOperationLimiter, asyncHandler(async (req, res) => {
  const { password, token } = req.body;
  const user = req.user;

  if (!user.mfaEnabled) {
    return res.status(400).json({
      success: false,
      message: 'MFA is not enabled'
    });
  }

  // Verify password
  if (!password || !(await user.comparePassword(password))) {
    await logSecurityEvent(req, 'mfa_disable_failed', 'Invalid password for MFA disable', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });
  }

  // Verify MFA token
  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'MFA token is required'
    });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
    window: 2
  });

  if (!verified) {
    await logSecurityEvent(req, 'mfa_disable_failed', 'Invalid MFA token for MFA disable', user._id, false);
    return res.status(400).json({
      success: false,
      message: 'Invalid MFA token'
    });
  }

  // Disable MFA
  user.mfaEnabled = false;
  user.mfaSecret = undefined;
  user.mfaBackupCodes = [];
  await user.save();

  await logSecurityEvent(req, 'mfa_disabled', 'MFA disabled successfully', user._id, true);

  res.json({
    success: true,
    message: 'MFA disabled successfully'
  });
}));

// Change password
router.put('/password', authenticateSession, sensitiveOperationLimiter, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must meet security requirements')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { currentPassword, newPassword } = req.body;
  const user = req.user;

  // Verify current password
  if (!(await user.comparePassword(currentPassword))) {
    await logSecurityEvent(req, 'password_change', 'Password change failed - invalid current password', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Current password is incorrect'
    });
  }

  // Check if new password is in history
  if (await user.isPasswordInHistory(newPassword)) {
    await logSecurityEvent(req, 'password_change', 'Password change failed - password reuse', user._id, false);
    return res.status(400).json({
      success: false,
      message: 'Cannot reuse recent passwords'
    });
  }

  // Update password
  user.password = newPassword;
  user.lastPasswordChange = new Date();
  await user.save();

  await logSecurityEvent(req, 'password_change', 'Password changed successfully', user._id, true);

  res.json({
    success: true,
    message: 'Password changed successfully'
  });
}));

// Password reset request
router.post('/password/reset-request', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { email } = req.body;
  const user = await User.findOne({ email });

  // Always return success to prevent email enumeration
  if (!user) {
    await logSecurityEvent(req, 'password_reset_request', 'Password reset requested for non-existent email', null, false);
    return res.json({
      success: true,
      message: 'If the email exists, a password reset link has been sent'
    });
  }

  // Generate reset token
  const resetToken = user.createPasswordResetToken();
  await user.save();

  await logSecurityEvent(req, 'password_reset_request', 'Password reset token generated', user._id, true);

  // Email service integration for password reset
  // For now, return the token (in production, this should be sent via email)
  res.json({
    success: true,
    message: 'Password reset link has been sent to your email',
    // Remove this in production
    resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
  });
}));

// Password reset
router.post('/password/reset', [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must meet security requirements')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { token, newPassword } = req.body;

  // Hash the token and find user
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!user) {
    await logSecurityEvent(req, 'password_reset', 'Password reset failed - invalid or expired token', null, false);
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired reset token'
    });
  }

  // Check password history
  if (await user.isPasswordInHistory(newPassword)) {
    await logSecurityEvent(req, 'password_reset', 'Password reset failed - password reuse', user._id, false);
    return res.status(400).json({
      success: false,
      message: 'Cannot reuse recent passwords'
    });
  }

  // Update password
  user.password = newPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  user.lastPasswordChange = new Date();

  // Reset login attempts
  await user.resetLoginAttempts();

  await user.save();

  await logSecurityEvent(req, 'password_reset', 'Password reset successful', user._id, true);

  res.json({
    success: true,
    message: 'Password reset successful'
  });
}));

// Get current user
router.get('/me', authenticateSession, asyncHandler(async (req, res) => {
  const user = req.user;

  res.json({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        accountNumber: user.accountNumber,
        balance: user.balance,
        mfaEnabled: user.mfaEnabled,
        lastLogin: user.lastLogin,
        isVerified: user.isVerified,
        createdAt: user.createdAt
      }
    }
  });
}));

module.exports = router;
