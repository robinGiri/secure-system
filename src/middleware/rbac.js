const { logSecurityEvent } = require('./auth');

// Role-based permissions configuration
const ROLE_PERMISSIONS = {
  admin: {
    // Full system access
    users: ['create', 'read', 'update', 'delete', 'manage'],
    transactions: ['create', 'read', 'update', 'delete', 'approve', 'review'],
    reports: ['create', 'read', 'export'],
    system: ['configure', 'monitor', 'audit'],
    audit: ['read', 'export'],
    roles: ['manage', 'assign'],
    settings: ['read', 'update']
  },
  manager: {
    // Limited management access
    users: ['read', 'update'],
    transactions: ['read', 'review', 'approve'],
    reports: ['create', 'read', 'export'],
    audit: ['read'],
    settings: ['read']
  },
  user: {
    // Basic user access
    profile: ['read', 'update'],
    transactions: ['create', 'read'],
    accounts: ['read']
  },
  viewer: {
    // Read-only access
    profile: ['read'],
    transactions: ['read'],
    accounts: ['read'],
    reports: ['read']
  }
};

// Resource-specific access controls
const RESOURCE_CONTROLS = {
  'users': {
    create: ['admin'],
    read: ['admin', 'manager', 'user'], // Users can read their own profile
    update: ['admin', 'manager', 'user'], // Users can update their own profile
    delete: ['admin'],
    manage: ['admin']
  },
  'transactions': {
    create: ['admin', 'manager', 'user'],
    read: ['admin', 'manager', 'user'], // Users can read their own transactions
    update: ['admin'],
    delete: ['admin'],
    approve: ['admin', 'manager'],
    review: ['admin', 'manager']
  },
  'reports': {
    create: ['admin', 'manager'],
    read: ['admin', 'manager', 'viewer'],
    export: ['admin', 'manager']
  },
  'audit': {
    read: ['admin', 'manager'],
    export: ['admin']
  },
  'system': {
    configure: ['admin'],
    monitor: ['admin'],
    audit: ['admin']
  },
  'roles': {
    manage: ['admin'],
    assign: ['admin']
  },
  'settings': {
    read: ['admin', 'manager'],
    update: ['admin']
  }
};

/**
 * Check if a user has permission for a specific resource and action
 * @param {Object} user - User object with role and permissions
 * @param {string} resource - Resource name (e.g., 'users', 'transactions')
 * @param {string} action - Action name (e.g., 'read', 'write', 'delete')
 * @returns {boolean} - True if user has permission
 */
const hasPermission = (user, resource, action) => {
  if (!user || !user.role) {
    return false;
  }

  // Admin has all permissions
  if (user.role === 'admin') {
    return true;
  }

  // Check role-based permissions
  const rolePermissions = ROLE_PERMISSIONS[user.role];
  if (rolePermissions && rolePermissions[resource] && rolePermissions[resource].includes(action)) {
    return true;
  }

  // Check resource-specific controls
  const resourceControl = RESOURCE_CONTROLS[resource];
  if (resourceControl && resourceControl[action] && resourceControl[action].includes(user.role)) {
    return true;
  }

  // Check custom user permissions
  if (user.permissions && Array.isArray(user.permissions)) {
    const permission = user.permissions.find(p => p.resource === resource);
    if (permission && permission.actions.includes(action)) {
      return true;
    }
  }

  return false;
};

/**
 * Middleware to check role-based access
 * @param {...string} allowedRoles - List of allowed roles
 * @returns {Function} - Express middleware function
 */
const requireRole = (...allowedRoles) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      await logSecurityEvent(
        req, 
        'authorization_failed', 
        `Role access denied. Required: ${allowedRoles.join(', ')}, Has: ${req.user.role}`,
        req.user._id, 
        false
      );
      
      return res.status(403).json({
        success: false,
        message: 'Insufficient privileges. Access denied.',
        required: allowedRoles,
        current: req.user.role
      });
    }

    next();
  };
};

/**
 * Middleware to check resource-based permissions
 * @param {string} resource - Resource name
 * @param {string} action - Action name
 * @returns {Function} - Express middleware function
 */
const requirePermission = (resource, action) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!hasPermission(req.user, resource, action)) {
      await logSecurityEvent(
        req, 
        'authorization_failed', 
        `Permission denied: ${action} on ${resource}`,
        req.user._id, 
        false
      );
      
      return res.status(403).json({
        success: false,
        message: `Permission denied: Cannot ${action} ${resource}`,
        resource,
        action,
        userRole: req.user.role
      });
    }

    next();
  };
};

/**
 * Middleware to check resource ownership or appropriate role
 * @param {string} userIdParam - Parameter name containing user ID
 * @param {Array} allowedRoles - Roles that can bypass ownership check
 * @returns {Function} - Express middleware function
 */
const requireOwnershipOrRole = (userIdParam = 'userId', allowedRoles = ['admin', 'manager']) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const targetUserId = req.params[userIdParam] || req.body[userIdParam];
    const currentUserId = req.user._id.toString();

    // Check if user is accessing their own resource
    if (targetUserId && targetUserId.toString() === currentUserId) {
      return next();
    }

    // Check if user has appropriate role
    if (allowedRoles.includes(req.user.role)) {
      return next();
    }

    await logSecurityEvent(
      req, 
      'authorization_failed', 
      `Ownership/role access denied for ${userIdParam}`,
      req.user._id, 
      false
    );

    return res.status(403).json({
      success: false,
      message: 'Access denied. You can only access your own resources or need appropriate role.',
      userRole: req.user.role,
      requiredRoles: allowedRoles
    });
  };
};

/**
 * Middleware to check transaction ownership
 * @returns {Function} - Express middleware function
 */
const requireTransactionAccess = () => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // Admin and manager can access all transactions
    if (['admin', 'manager'].includes(req.user.role)) {
      return next();
    }

    const transactionId = req.params.transactionId || req.params.id;
    if (!transactionId) {
      return res.status(400).json({
        success: false,
        message: 'Transaction ID required'
      });
    }

    try {
      const Transaction = require('../models/Transaction');
      const transaction = await Transaction.findById(transactionId);

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: 'Transaction not found'
        });
      }

      const userId = req.user._id.toString();
      const isOwner = transaction.fromAccount.toString() === userId || 
                     transaction.toAccount.toString() === userId;

      if (!isOwner) {
        await logSecurityEvent(
          req, 
          'authorization_failed', 
          `Unauthorized transaction access attempt: ${transactionId}`,
          req.user._id, 
          false
        );

        return res.status(403).json({
          success: false,
          message: 'Access denied. You can only access your own transactions.'
        });
      }

      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: 'Error checking transaction access'
      });
    }
  };
};

/**
 * Get user's effective permissions
 * @param {Object} user - User object
 * @returns {Object} - Object containing all permissions
 */
const getUserPermissions = (user) => {
  if (!user || !user.role) {
    return {};
  }

  const permissions = {};
  
  // Add role-based permissions
  const rolePermissions = ROLE_PERMISSIONS[user.role] || {};
  Object.keys(rolePermissions).forEach(resource => {
    if (!permissions[resource]) {
      permissions[resource] = [];
    }
    permissions[resource] = [...new Set([...permissions[resource], ...rolePermissions[resource]])];
  });

  // Add custom user permissions
  if (user.permissions && Array.isArray(user.permissions)) {
    user.permissions.forEach(permission => {
      if (!permissions[permission.resource]) {
        permissions[permission.resource] = [];
      }
      permissions[permission.resource] = [...new Set([...permissions[permission.resource], ...permission.actions])];
    });
  }

  return permissions;
};

/**
 * Middleware to add user permissions to request
 */
const addUserPermissions = (req, res, next) => {
  if (req.user) {
    req.user.effectivePermissions = getUserPermissions(req.user);
  }
  next();
};

module.exports = {
  hasPermission,
  requireRole,
  requirePermission,
  requireOwnershipOrRole,
  requireTransactionAccess,
  getUserPermissions,
  addUserPermissions,
  ROLE_PERMISSIONS,
  RESOURCE_CONTROLS
};
