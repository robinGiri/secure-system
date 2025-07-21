<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Secure Banking Application - Copilot Instructions

This is a secure banking web application built for a security assignment (ST6005CEM). The application demonstrates comprehensive security measures including authentication, authorization, encryption, and audit logging.

## Project Structure

- `src/app.js` - Main application entry point
- `src/models/` - MongoDB/Mongoose data models
- `src/routes/` - Express route handlers
- `src/middleware/` - Custom middleware (auth, audit, error handling)
- `src/utils/` - Utility functions for security operations
- `views/` - EJS templates for frontend
- `public/` - Static assets (CSS, JS, images)
- `logs/` - Application and audit logs

## Security Features Implemented

1. **Authentication & Authorization**
   - Multi-Factor Authentication (MFA) using TOTP
   - Role-Based Access Control (RBAC)
   - JWT and session-based authentication
   - Account lockout after failed attempts

2. **Data Protection**
   - Password hashing with bcrypt
   - Data encryption at rest
   - Input validation and sanitization
   - Secure password policies with history tracking

3. **Security Measures**
   - Comprehensive audit logging
   - Rate limiting and brute-force protection
   - CORS and security headers (Helmet.js)
   - Real-time fraud detection
   - Session management with secure cookies

4. **Monitoring & Auditing**
   - Winston logging for audit trails
   - Security event monitoring
   - Activity tracking and reporting
   - Risk assessment for transactions

## Code Style Guidelines

- Use async/await for asynchronous operations
- Implement proper error handling with try-catch blocks
- Follow RESTful API conventions
- Use middleware for cross-cutting concerns
- Validate all inputs using express-validator
- Log security events using the audit middleware
- Follow the principle of least privilege for access control

## Security Considerations

- Never log sensitive data (passwords, tokens, personal info)
- Always validate and sanitize user inputs
- Use parameterized queries to prevent SQL injection
- Implement proper session management
- Use HTTPS in production
- Keep dependencies updated and audit for vulnerabilities
- Follow OWASP security best practices

## Environment Variables

Key environment variables used:
- `MONGODB_URI` - Database connection string
- `JWT_SECRET` - JWT signing secret
- `SESSION_SECRET` - Session encryption secret
- `ENCRYPTION_KEY` - Data encryption key
- `NODE_ENV` - Environment (development/production)

## Testing

- Write unit tests for utility functions
- Test API endpoints with proper authentication
- Validate security measures (rate limiting, MFA)
- Test error handling and edge cases

When generating code for this project, prioritize security, follow the established patterns, and ensure all new features include proper validation, authorization, and audit logging.
