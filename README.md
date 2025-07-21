# Secure Banking Application

A comprehensive secure web application built for the Security module (ST6005CEM) assignment, demonstrating industry-standard security practices in modern web development.

## 🏆 Assignment Information

- **Module:** Security (ST6005CEM)
- **Assignment:** Individual Report - Secure Web Application
- **Due Date:** 1 August 2025
- **Weight:** 50% (Core Assessment)
- **Institution:** Softwarica College of IT & E-Commerce (in collaboration with Coventry University)

## 🔒 Security Features Implemented

### Core Security Requirements

#### 1. User Authentication & Registration
- ✅ Secure user registration with email verification
- ✅ Multi-Factor Authentication (MFA) using Time-based OTP
- ✅ Account lockout after failed login attempts
- ✅ Session management with secure cookies
- ✅ Password reset with secure token generation

#### 2. Password Security
- ✅ **Password Policy Enforcement:**
  - Minimum 8 characters, maximum 128 characters
  - Mix of uppercase, lowercase, numbers, and special characters
  - Password history tracking (prevents reuse of last 5 passwords)
  - Password expiry (90 days by default)
  - Real-time strength assessment during registration

#### 3. Brute-Force Prevention
- ✅ Rate limiting on login attempts (5 attempts per 15 minutes)
- ✅ Account lockout mechanism (2 hours after 5 failed attempts)
- ✅ IP-based rate limiting for sensitive operations
- ✅ Progressive delays for failed authentication

#### 4. Role-Based Access Control (RBAC)
- ✅ User roles: `user`, `admin`, `manager`, `viewer`
- ✅ Permission-based resource access
- ✅ Route-level authorization middleware
- ✅ Resource ownership validation

#### 5. Session Management
- ✅ Secure session creation with MongoDB store
- ✅ Session expiration (30 minutes of inactivity)
- ✅ Secure session headers and CSRF protection
- ✅ Session tracking and management
- ✅ Automatic session cleanup

#### 6. Encryption & Data Protection
- ✅ Password hashing with bcrypt (12 rounds)
- ✅ Sensitive data encryption (AES-256-GCM)
- ✅ Data integrity verification with checksums
- ✅ Secure token generation for password reset/verification

#### 7. Activity Logging & Auditing
- ✅ Comprehensive audit trail for all user actions
- ✅ Security event monitoring and alerting
- ✅ Failed login attempt tracking
- ✅ Admin action logging
- ✅ Winston-based structured logging

### Advanced Security Features

#### 8. Transaction Security
- ✅ Secure transaction processing with atomic operations
- ✅ Risk assessment and fraud detection
- ✅ Transaction encryption and integrity verification
- ✅ Real-time transaction monitoring

#### 9. Input Validation & Sanitization
- ✅ Express-validator for input validation
- ✅ XSS prevention with input sanitization
- ✅ SQL injection prevention
- ✅ Command injection protection

#### 10. Security Headers & CORS
- ✅ Helmet.js for security headers
- ✅ CORS configuration
- ✅ Content Security Policy (CSP)
- ✅ HSTS (HTTP Strict Transport Security)

## 🛠 Technical Stack

### Backend
- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB with Mongoose ODM
- **Authentication:** JWT + Session-based
- **Password Hashing:** bcryptjs
- **MFA:** Speakeasy (TOTP)
- **Logging:** Winston
- **Validation:** express-validator

### Security Libraries
- **Helmet.js** - Security headers
- **express-rate-limit** - Rate limiting
- **cors** - Cross-Origin Resource Sharing
- **crypto** - Cryptographic operations
- **speakeasy** - Time-based OTP for MFA
- **qrcode** - QR code generation for MFA setup

### Frontend
- **Template Engine:** EJS
- **CSS Framework:** Bootstrap 5
- **Icons:** Font Awesome
- **Responsive Design:** Mobile-first approach

## 📁 Project Structure

```
security/
├── src/
│   ├── app.js                 # Main application entry point
│   ├── models/
│   │   ├── User.js           # User model with security features
│   │   ├── Transaction.js    # Transaction model with encryption
│   │   └── AuditLog.js      # Audit logging model
│   ├── routes/
│   │   ├── auth.js          # Authentication routes
│   │   ├── user.js          # User management routes
│   │   ├── admin.js         # Admin panel routes
│   │   └── transaction.js   # Transaction routes
│   ├── middleware/
│   │   ├── auth.js          # Authentication & authorization
│   │   ├── auditLogger.js   # Audit logging middleware
│   │   └── errorHandler.js  # Error handling middleware
│   └── utils/
│       └── security.js      # Security utility functions
├── views/
│   ├── layout.ejs           # Main layout template
│   ├── index.ejs            # Homepage
│   └── 404.ejs              # Error page
├── public/                  # Static assets
├── logs/                    # Application logs
├── .env.example             # Environment variables template
├── .gitignore              # Git ignore rules
└── README.md               # Project documentation
```

## 🚀 Installation & Setup

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (v4.4 or higher)
- Git

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd security
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

4. **Start MongoDB**
   ```bash
   # On macOS with Homebrew
   brew services start mongodb/brew/mongodb-community

   # On Ubuntu/Linux
   sudo systemctl start mongod

   # On Windows
   net start MongoDB
   ```

5. **Start the application**
   ```bash
   # Development mode with auto-reload
   npm run dev

   # Production mode
   npm start
   ```

6. **Access the application**
   - Open browser and navigate to `http://localhost:3000`

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Database
MONGODB_URI=mongodb://localhost:27017/security_app

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=1h

# Session Configuration
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Application
NODE_ENV=development
PORT=3000

# Encryption
ENCRYPTION_KEY=your-32-character-encryption-key-12

# Password Policy
MIN_PASSWORD_LENGTH=8
MAX_PASSWORD_LENGTH=128
PASSWORD_EXPIRY_DAYS=90
PASSWORD_HISTORY_COUNT=5

# MFA Configuration
MFA_ISSUER=SecureBankingApp
MFA_WINDOW=2
```

## 📝 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/mfa/enable` - Enable MFA
- `POST /api/auth/mfa/verify` - Verify MFA token
- `PUT /api/auth/password` - Change password
- `POST /api/auth/password/reset-request` - Request password reset
- `POST /api/auth/password/reset` - Reset password

### User Management
- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update user profile
- `GET /api/user/sessions` - Get active sessions
- `DELETE /api/user/sessions/:sessionId` - Terminate session
- `GET /api/user/activity` - Get user activity log

### Transactions
- `GET /api/transactions` - Get user transactions
- `POST /api/transactions` - Create new transaction
- `GET /api/transactions/:id` - Get transaction details
- `PATCH /api/transactions/:id/cancel` - Cancel transaction

### Admin (Admin Role Required)
- `GET /api/admin/dashboard` - Admin dashboard
- `GET /api/admin/users` - Manage users
- `GET /api/admin/transactions` - View all transactions
- `GET /api/admin/audit-logs` - View audit logs
- `GET /api/admin/security/report` - Security report

## 🧪 Testing

### Running Tests
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run security audit
npm run security-audit
```

### Test Coverage
- Authentication flow testing
- Authorization middleware testing
- Input validation testing
- Security feature testing

## 🔍 Security Testing & Penetration Testing

### Internal Security Audit

The application includes comprehensive security measures that can be tested:

1. **Authentication Testing**
   - Test brute-force protection
   - Verify MFA implementation
   - Test session management

2. **Authorization Testing**
   - Test role-based access control
   - Verify resource ownership checks
   - Test privilege escalation attempts

3. **Input Validation Testing**
   - Test XSS prevention
   - Test SQL injection prevention
   - Test command injection prevention

4. **Security Headers Testing**
   - Verify CSP implementation
   - Test HSTS headers
   - Check CORS configuration

### Vulnerability Assessment

Regular security assessments should include:
- Dependency vulnerability scanning (`npm audit`)
- Static code analysis
- Dynamic security testing
- Manual penetration testing

## 📊 Monitoring & Logging

### Audit Logging
All security-relevant events are logged including:
- User authentication attempts
- Authorization failures
- Data access and modifications
- Administrative actions
- Security violations

### Log Files
- `logs/audit.log` - Comprehensive audit trail
- `logs/security-events.log` - Security-specific events
- Console output in development mode

### Monitoring Features
- Real-time security event monitoring
- Failed login attempt tracking
- Suspicious activity detection
- System health monitoring

## 🚀 Deployment

### Production Deployment Checklist

Before deploying to production:

1. **Security Configuration**
   - [ ] Change all default secrets and keys
   - [ ] Enable HTTPS/TLS
   - [ ] Configure production database
   - [ ] Set NODE_ENV=production
   - [ ] Enable security headers

2. **Environment Setup**
   - [ ] Secure server configuration
   - [ ] Firewall configuration
   - [ ] Reverse proxy setup (nginx/Apache)
   - [ ] SSL certificate installation

3. **Database Security**
   - [ ] Enable MongoDB authentication
   - [ ] Configure database firewall
   - [ ] Set up database backups
   - [ ] Enable encryption at rest

4. **Monitoring**
   - [ ] Set up log aggregation
   - [ ] Configure alerting
   - [ ] Monitor security events
   - [ ] Set up health checks

## 🤝 Contributing

This is an academic project for assignment submission. For educational purposes, you may:

1. Fork the repository
2. Create a feature branch
3. Implement additional security features
4. Add comprehensive tests
5. Submit a pull request with detailed documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎓 Academic Context

This application was developed as part of the Security module (ST6005CEM) for Softwarica College of IT & E-Commerce in collaboration with Coventry University. It demonstrates practical implementation of security concepts learned in the course.

### Learning Outcomes Demonstrated

1. **LO1:** Critical evaluation of encryption and authentication methods
2. **LO2:** Systematic knowledge to create secure environments
3. **LO3:** Development and evaluation of software addressing security concerns

## 📞 Support

For academic inquiries related to this assignment:
- **Module Leader:** Arya Pokharel
- **Email:** stw00105@softwarica.edu.np

---

**⚠️ Important Note:** This application is developed for educational purposes as part of a security assignment. While it implements real security measures, it should not be used in production without additional security reviews and hardening.

**🔐 Security Disclaimer:** Always conduct thorough security testing and follow current security best practices when deploying applications in production environments.
