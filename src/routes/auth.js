const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const { detectSuspiciousActivity, applySecurityMeasures } = require('../utils/securityUtils');

// Function to validate password strength beyond basic regex
function validatePasswordStrength(password) {
  // Initial checks (already handled by express-validator)
  if (password.length < 8) {
    return { 
      isStrong: false, 
      message: 'Password must be at least 8 characters long',
      feedback: ['Use a longer password'] 
    };
  }
  
  // Check for common passwords
  const commonPasswords = [
    'password', 'admin123', '12345678', 'qwerty123', 'letmein', 
    'welcome', 'monkey123', 'password123', '123456789', 'abc123'
  ];
  
  if (commonPasswords.includes(password.toLowerCase())) {
    return { 
      isStrong: false, 
      message: 'This password is too common and easily guessed',
      feedback: ['Choose a less common password', 'Avoid dictionary words'] 
    };
  }
  
  // Check for repeating patterns
  if (/(.)\1{2,}/.test(password)) { // Same character 3+ times in a row
    return { 
      isStrong: false, 
      message: 'Password contains repeating characters',
      feedback: ['Avoid repeating characters like "aaa" or "111"'] 
    };
  }
  
  // Check for sequential patterns
  if (/(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
    return { 
      isStrong: false, 
      message: 'Password contains sequential patterns',
      feedback: ['Avoid sequential patterns like "123" or "abc"'] 
    };
  }
  
  // Advanced scoring
  let score = 0;
  
  // Length - up to 30 points
  score += Math.min(30, password.length * 2);
  
  // Character variety - up to 40 points
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/[0-9]/.test(password)) score += 10;
  if (/[^A-Za-z0-9]/.test(password)) score += 10;
  
  // Length of unique characters - up to 30 points
  const uniqueChars = new Set(password.split('')).size;
  score += Math.min(30, uniqueChars * 2);
  
  if (score >= 60) {
    return { isStrong: true };
  } else {
    return {
      isStrong: false,
      message: 'Password is not strong enough',
      feedback: [
        'Use a longer password',
        'Include a mix of uppercase, lowercase, numbers and special characters',
        'Avoid patterns and common words'
      ]
    };
  }
}

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

  const { username, email, password, firstName, lastName, phoneNumber, captchaToken } = req.body;

  // Debug logging for CAPTCHA requirement
  console.log('CAPTCHA Debug:', {
    captchaToken: !!captchaToken,
    REQUIRE_CAPTCHA: process.env.REQUIRE_CAPTCHA,
    shouldRequire: process.env.REQUIRE_CAPTCHA !== 'false'
  });

  // Verify CAPTCHA token (required for registration to prevent automated attacks)
  // This is a placeholder for actual CAPTCHA verification logic
  if (!captchaToken && process.env.REQUIRE_CAPTCHA !== 'false') {
    await logSecurityEvent(req, 'registration_failed', 'CAPTCHA required but not provided', null, false);
    return res.status(400).json({
      success: false,
      message: 'CAPTCHA verification failed',
      requireCaptcha: true
    });
  }

  // Check for existing users
  const existingUser = await User.findOne({
    $or: [{ email }, { username }]
  });

  if (existingUser) {
    await logSecurityEvent(req, 'user_registration', 'Registration failed - user already exists', null, false);
    
    // For security, don't specify whether email or username already exists
    return res.status(400).json({
      success: false,
      message: 'A user with this email or username already exists'
    });
  }

  // Check for suspicious patterns (multiple registrations from same IP)
  const recentRegistrations = await AuditLog.countDocuments({
    ipAddress: req.ip,
    eventType: 'user_registration',
    createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
  });

  if (recentRegistrations >= 5) {
    await logSecurityEvent(req, 'registration_blocked', 'Too many registration attempts from IP', null, false);
    await logSecurityIncident(req, 'excessive_registrations', `IP ${req.ip} attempted multiple registrations`, 'medium');
    
    return res.status(429).json({
      success: false,
      message: 'Too many registration attempts. Please try again later.'
    });
  }

  // Check password strength beyond basic regex
  const passwordCheck = validatePasswordStrength(password);
  if (!passwordCheck.isStrong) {
    return res.status(400).json({
      success: false,
      message: passwordCheck.message,
      feedback: passwordCheck.feedback
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
    role: 'user',
    isVerified: process.env.REQUIRE_EMAIL_VERIFICATION !== 'false' ? false : true // Skip verification in development
  });

  await user.save();

  // Generate verification token only if email verification is required
  let verificationToken;
  if (process.env.REQUIRE_EMAIL_VERIFICATION !== 'false') {
    verificationToken = user.createVerificationToken();
    await user.save();
  }

  await logSecurityEvent(req, 'user_registration', 'User registered successfully', user._id, true);
  
  // In production, an email would be sent with the verification token
  // For development, we'll include the token in the response

  const requireEmailVerification = process.env.REQUIRE_EMAIL_VERIFICATION !== 'false';

  // Send verification email in production
  // For development, include verification token in response
  res.status(201).json({
    success: true,
    message: requireEmailVerification 
      ? 'User registered successfully. Please verify your email to activate your account.'
      : 'User registered successfully. You can now log in.',
    data: {
      userId: user._id,
      username: user.username,
      email: user.email,
      accountNumber: user.accountNumber,
      requireEmailVerification,
      // Remove these in production
      verificationToken: (process.env.NODE_ENV === 'development' && verificationToken) ? verificationToken : undefined,
      verificationInstructions: verificationToken ? 'Use the verification token to verify your email address.' : undefined
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

  const { username, password, mfaToken, captchaToken } = req.body;

  // Verify CAPTCHA token if required globally or after suspicious activity
  // This is a placeholder for actual CAPTCHA verification logic
  const requireCaptcha = req.session.requireCaptcha || process.env.REQUIRE_CAPTCHA === 'true';
  if (requireCaptcha && !captchaToken) {
    await logSecurityEvent(req, 'login_failed', 'CAPTCHA required but not provided', null, false);
    return res.status(401).json({
      success: false,
      message: 'Please complete the CAPTCHA verification',
      requireCaptcha: true
    });
  }

  // Find user by username or email
  const user = await User.findOne({
    $or: [{ username }, { email: username }]
  }).select('+mfaSecret');

  if (!user) {
    // Set session flag if multiple failed attempts are detected from this IP
    const ipLoginAttempts = await AuditLog.countDocuments({
      ipAddress: req.ip, 
      eventType: 'login_failed', 
      createdAt: { $gt: new Date(Date.now() - 15 * 60 * 1000) } // Last 15 minutes
    });

    if (ipLoginAttempts >= 3) {
      req.session.requireCaptcha = true;
    }

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
    const lockTime = new Date(user.lockUntil);
    const unlockTime = new Date(user.lockUntil).toLocaleString();
    const reason = user.lockReason || 'multiple failed login attempts';
    
    await logSecurityEvent(req, 'login_failed', `Account locked: ${reason}`, user._id, false);
    return res.status(401).json({
      success: false,
      message: `Your account is temporarily locked due to ${reason}. Please try again after ${unlockTime}.`,
      lockedUntil: lockTime
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
  
  // Check if email is verified (only if verification is required)
  if (!user.isVerified && process.env.REQUIRE_EMAIL_VERIFICATION !== 'false') {
    await logSecurityEvent(req, 'login_failed', 'Email not verified', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Please verify your email address before logging in.',
      requireVerification: true,
      userId: user._id
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
      // Create a session with limited capabilities - only valid for MFA verification
      req.session.pendingUserId = user._id.toString();
      req.session.pendingUsername = user.username;
      req.session.pendingMfa = true;
      req.session.mfaExpiry = Date.now() + 5 * 60 * 1000; // 5 minute window to complete MFA
      
      return res.status(200).json({
        success: false,
        requireMFA: true,
        message: 'Multi-factor authentication required',
        username: user.username,
        email: user.email.replace(/^(.{3})(.*)(@.*)$/, '$1****$3'), // Mask email for display
        mfaSessionValid: true
      });
    }

    // Support both TOTP and backup codes
    let verified = false;
    
    // Check if it's a backup code (format: typically alphanumeric codes of fixed length)
    if (/^[A-Z0-9]{8,12}$/.test(mfaToken)) {
      // Find and verify backup code
      const backupCodeIndex = user.mfaBackupCodes.findIndex(
        bc => !bc.used && bc.code === mfaToken
      );
      
      if (backupCodeIndex >= 0) {
        // Mark backup code as used
        user.mfaBackupCodes[backupCodeIndex].used = true;
        await user.save();
        verified = true;
        await logSecurityEvent(req, 'mfa_verified', 'MFA verified with backup code', user._id, true);
      }
    } else {
      // Verify TOTP code
      verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: mfaToken,
        window: parseInt(process.env.MFA_WINDOW) || 2
      });
      
      if (verified) {
        await logSecurityEvent(req, 'mfa_verified', 'MFA verification successful with TOTP', user._id, true);
      }
    }

    if (!verified) {
      await user.incLoginAttempts();
      await logSecurityEvent(req, 'mfa_failed', 'MFA verification failed', user._id, false);
      return res.status(401).json({
        success: false,
        message: 'Invalid MFA token',
        remainingAttempts: Math.max(0, 5 - user.loginAttempts)
      });
    }

    req.session.mfaVerified = true;
    delete req.session.pendingMfa;
    delete req.session.pendingUserId;
    delete req.session.pendingUsername;
    delete req.session.mfaExpiry;
  }

  // Reset login attempts on successful login
  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }

  // Check for suspicious activity
  const suspiciousActivity = await detectSuspiciousActivity(req, user);
  if (suspiciousActivity.riskLevel !== 'low') {
    await logSecurityEvent(
      req, 
      'suspicious_login', 
      `Suspicious login detected: ${suspiciousActivity.anomalies.join(', ')}`,
      user._id,
      true
    );
    
    // Apply appropriate security measures
    await applySecurityMeasures(req, user, suspiciousActivity);
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
    message: suspiciousActivity && suspiciousActivity.anomalies?.length > 0 
      ? 'Login successful. We noticed unusual activity on your account.'
      : 'Login successful',
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        accountNumber: user.accountNumber,
        mfaEnabled: user.mfaEnabled,
        isVerified: user.isVerified,
        lastLogin: user.lastLogin
      },
      token,
      sessionId: req.sessionID,
      sessionExpiresAt: req.session.cookie.expires,
      securityInfo: suspiciousActivity && suspiciousActivity.anomalies?.length > 0 ? {
        newDevice: suspiciousActivity.isNewDevice || false,
        newLocation: suspiciousActivity.isNewLocation || false,
        suspiciousActivity: suspiciousActivity.riskLevel !== 'low',
        recommendMfa: !user.mfaEnabled && (suspiciousActivity.riskLevel !== 'low')
      } : undefined
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
  const { currentPassword } = req.body;
  const user = req.user;

  // Require current password for enabling MFA
  if (!currentPassword) {
    return res.status(400).json({
      success: false,
      message: 'Current password is required to enable MFA'
    });
  }

  // Verify current password
  const isPasswordValid = await user.comparePassword(currentPassword);
  if (!isPasswordValid) {
    await logSecurityEvent(req, 'mfa_enable_failed', 'Invalid password for MFA setup', user._id, false);
    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });
  }

  if (user.mfaEnabled) {
    return res.status(400).json({
      success: false,
      message: 'MFA is already enabled'
    });
  }

  // Generate a more secure secret
  const secret = speakeasy.generateSecret({
    name: `${process.env.MFA_ISSUER || 'Robin Bank'}:${user.email}`,
    issuer: process.env.MFA_ISSUER || 'Robin Bank',
    length: 32
  });

  // Generate QR code with better rendering options
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url, {
    errorCorrectionLevel: 'H',
    type: 'image/png',
    quality: 0.92,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#FFFFFF'
    }
  });

  // Save secret to user (will be confirmed when first token is verified)
  user.mfaSecret = secret.base32;
  await user.save();

  await logSecurityEvent(req, 'mfa_setup_initiated', 'MFA setup process started', user._id, true);

  res.json({
    success: true,
    message: 'MFA setup initiated',
    data: {
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      email: user.email,
      issuer: process.env.MFA_ISSUER || 'Robin Bank'
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

  // Verify token with a small window to account for time drift
  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
    window: 2  // Allow 2 intervals before/after for time drift (±1 minute with 30s intervals)
  });

  if (!verified) {
    // Log failed verification attempt
    await logSecurityEvent(req, 'mfa_verification_failed', 'MFA verification failed during setup', user._id, false);
    return res.status(400).json({
      success: false,
      message: 'Invalid MFA token. Please make sure your authenticator app is properly synchronized.'
    });
  }

  // Enable MFA
  user.mfaEnabled = true;

  // Generate more secure backup codes (longer, more complex)
  const backupCodes = [];
  
  // Format: 4 blocks of 4 characters (more readable and secure)
  // Example: AXDF-9G3H-JK4L-QW3Z
  for (let i = 0; i < 8; i++) {
    // Generate a more secure backup code with mixed alphanumeric characters
    const blockA = crypto.randomBytes(2).toString('hex').toUpperCase();
    const blockB = crypto.randomBytes(2).toString('hex').toUpperCase();
    const blockC = crypto.randomBytes(2).toString('hex').toUpperCase();
    const blockD = crypto.randomBytes(2).toString('hex').toUpperCase();
    
    const code = `${blockA}-${blockB}-${blockC}-${blockD}`;
    backupCodes.push(code);
    
    // Store only the concatenated version (without hyphens) in the database
    const storedCode = `${blockA}${blockB}${blockC}${blockD}`;
    user.mfaBackupCodes.push({ 
      code: storedCode,
      used: false,
      createdAt: new Date()
    });
  }

  // Record last time MFA was updated
  user.lastMfaUpdate = new Date();
  
  await user.save();

  await logSecurityEvent(req, 'mfa_enabled', 'MFA enabled successfully', user._id, true);

  // Recommend user to save backup codes
  res.json({
    success: true,
    message: 'MFA enabled successfully. Please save your backup codes in a secure location.',
    data: {
      backupCodes,
      recoveryCodesCount: backupCodes.length,
      mfaEnabled: true,
      nextStep: 'Please store your backup codes safely. You will need them if you lose access to your authenticator app.'
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

// Email verification route
router.post('/verify-email', asyncHandler(async (req, res) => {
  const { token, userId } = req.body;
  
  if (!token || !userId) {
    return res.status(400).json({
      success: false,
      message: 'Verification token and user ID are required'
    });
  }

  // Find user
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Check if already verified
  if (user.isVerified) {
    return res.status(400).json({
      success: false,
      message: 'Email is already verified'
    });
  }

  // Check if token exists and is not expired
  if (!user.verificationToken || !user.verificationTokenExpires) {
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired verification token'
    });
  }

  if (user.verificationTokenExpires < Date.now()) {
    return res.status(400).json({
      success: false,
      message: 'Verification token has expired. Please request a new one'
    });
  }

  // Hash the token and compare
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  if (hashedToken !== user.verificationToken) {
    await logSecurityEvent(req, 'email_verification_failed', 'Invalid verification token', user._id, false);
    return res.status(400).json({
      success: false,
      message: 'Invalid verification token'
    });
  }

  // Verify the email
  user.isVerified = true;
  user.verificationToken = undefined;
  user.verificationTokenExpires = undefined;

  await user.save();

  await logSecurityEvent(req, 'email_verified', 'Email verified successfully', user._id, true);

  res.json({
    success: true,
    message: 'Email verified successfully. You can now log in.'
  });
}));

// Resend verification email
router.post('/resend-verification', [
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
  
  // Find user by email
  const user = await User.findOne({ email });
  
  // Don't reveal if user exists
  if (!user) {
    return res.json({
      success: true,
      message: 'If the email exists in our system, a verification link has been sent.'
    });
  }

  // Check if already verified
  if (user.isVerified) {
    return res.json({
      success: true,
      message: 'This email is already verified. Please log in.'
    });
  }

  // Generate new verification token
  const verificationToken = user.createVerificationToken();
  await user.save();

  await logSecurityEvent(req, 'verification_email_resent', 'Verification email resent', user._id, true);

  // In production, send email with verification link
  
  // For development, return token
  res.json({
    success: true,
    message: 'Verification email has been sent. Please check your inbox.',
    // Remove this in production
    verificationToken: process.env.NODE_ENV === 'development' ? verificationToken : undefined,
    userId: process.env.NODE_ENV === 'development' ? user._id : undefined
  });
}));

// Account recovery endpoint
router.post('/account-recovery', [
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

  const { email, captchaToken } = req.body;
  
  // Verify CAPTCHA token if provided
  // This is a placeholder for actual CAPTCHA verification logic
  if (!captchaToken && process.env.REQUIRE_CAPTCHA !== 'false') {
    return res.status(400).json({
      success: false,
      message: 'CAPTCHA verification failed',
      requireCaptcha: true
    });
  }

  // Don't reveal if user exists
  const user = await User.findOne({ email });
  if (!user) {
    return res.json({
      success: true,
      message: 'If the email exists in our system, recovery instructions have been sent.'
    });
  }

  // Check for excessive recovery attempts
  const recentAttempts = await AuditLog.countDocuments({
    userId: user._id,
    eventType: 'account_recovery',
    createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
  });

  if (recentAttempts >= 3) {
    await logSecurityEvent(req, 'recovery_limited', 'Too many recovery attempts', user._id, false);
    return res.json({
      success: true,
      message: 'If the email exists in our system, recovery instructions have been sent.'
    });
  }

  // Generate recovery token and instructions
  const recoveryToken = crypto.randomBytes(32).toString('hex');
  user.recoveryToken = crypto.createHash('sha256').update(recoveryToken).digest('hex');
  user.recoveryTokenExpires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour
  await user.save();

  await logSecurityEvent(req, 'account_recovery', 'Account recovery requested', user._id, true);

  // In production, send email with recovery instructions
  
  // For development, return token
  res.json({
    success: true,
    message: 'Recovery instructions have been sent to your email.',
    // Remove this in production
    recoveryToken: process.env.NODE_ENV === 'development' ? recoveryToken : undefined,
    userId: process.env.NODE_ENV === 'development' ? user._id : undefined
  });
}));

// Check if CAPTCHA is required for login
router.get('/captcha-required', (req, res) => {
  const requireCaptcha = req.session.requireCaptcha || process.env.REQUIRE_CAPTCHA === 'true';
  res.json({
    success: true,
    requireCaptcha: requireCaptcha
  });
});

module.exports = router;
