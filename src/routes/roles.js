const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { 
  authenticateSession, 
  requireRole,
  requirePermission,
  addUserPermissions,
  sensitiveOperationLimiter 
} = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityEvent } = require('../middleware/auth');
const { ROLE_PERMISSIONS, RESOURCE_CONTROLS } = require('../middleware/rbac');

const router = express.Router();

// All role management routes require authentication and admin privileges
router.use(authenticateSession);
router.use(requireRole('admin'));
router.use(addUserPermissions);

// Get all available roles and their permissions
router.get('/roles', requirePermission('roles', 'manage'), asyncHandler(async (req, res) => {
  await logSecurityEvent(req, 'role_management', 'Retrieved role permissions structure', req.user._id, true);

  res.json({
    success: true,
    data: {
      roles: Object.keys(ROLE_PERMISSIONS),
      permissions: ROLE_PERMISSIONS,
      resourceControls: RESOURCE_CONTROLS
    }
  });
}));

// Assign role to user
router.put('/users/:userId/role', requirePermission('roles', 'assign'), sensitiveOperationLimiter, [
  body('role').isIn(['user', 'admin', 'manager', 'viewer']).withMessage('Invalid role')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { userId } = req.params;
  const { role } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  const oldRole = user.role;
  user.role = role;
  await user.save();

  await logSecurityEvent(
    req, 
    'role_assignment', 
    `Role changed from ${oldRole} to ${role} for user ${user.username}`,
    req.user._id, 
    true
  );

  res.json({
    success: true,
    message: `User role updated to ${role}`,
    data: {
      userId: user._id,
      username: user.username,
      oldRole,
      newRole: role
    }
  });
}));

// Add custom permission to user
router.post('/users/:userId/permissions', requirePermission('roles', 'manage'), sensitiveOperationLimiter, [
  body('resource').isLength({ min: 1, max: 50 }).withMessage('Resource name is required'),
  body('actions').isArray({ min: 1 }).withMessage('Actions array is required'),
  body('actions.*').isIn(['create', 'read', 'update', 'delete', 'manage', 'approve', 'review', 'export']).withMessage('Invalid action')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { userId } = req.params;
  const { resource, actions } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Check if permission already exists for this resource
  const existingPermissionIndex = user.permissions.findIndex(p => p.resource === resource);
  
  if (existingPermissionIndex !== -1) {
    // Update existing permission
    user.permissions[existingPermissionIndex].actions = [...new Set([
      ...user.permissions[existingPermissionIndex].actions,
      ...actions
    ])];
  } else {
    // Add new permission
    user.permissions.push({ resource, actions });
  }

  await user.save();

  await logSecurityEvent(
    req, 
    'permission_granted', 
    `Custom permissions added for ${resource}: ${actions.join(', ')} to user ${user.username}`,
    req.user._id, 
    true
  );

  res.json({
    success: true,
    message: 'Permissions added successfully',
    data: {
      userId: user._id,
      username: user.username,
      resource,
      actions,
      allPermissions: user.permissions
    }
  });
}));

// Remove custom permission from user
router.delete('/users/:userId/permissions/:resource', requirePermission('roles', 'manage'), sensitiveOperationLimiter, asyncHandler(async (req, res) => {
  const { userId, resource } = req.params;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  const permissionIndex = user.permissions.findIndex(p => p.resource === resource);
  if (permissionIndex === -1) {
    return res.status(404).json({
      success: false,
      message: 'Permission not found'
    });
  }

  const removedPermission = user.permissions[permissionIndex];
  user.permissions.splice(permissionIndex, 1);
  await user.save();

  await logSecurityEvent(
    req, 
    'permission_revoked', 
    `Custom permissions removed for ${resource} from user ${user.username}`,
    req.user._id, 
    true
  );

  res.json({
    success: true,
    message: 'Permission removed successfully',
    data: {
      userId: user._id,
      username: user.username,
      removedPermission,
      remainingPermissions: user.permissions
    }
  });
}));

// Get user's effective permissions
router.get('/users/:userId/permissions', requirePermission('roles', 'manage'), asyncHandler(async (req, res) => {
  const { userId } = req.params;

  const user = await User.findById(userId).select('username role permissions');
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Get role-based permissions
  const rolePermissions = ROLE_PERMISSIONS[user.role] || {};
  
  // Combine with custom permissions
  const effectivePermissions = {};
  
  // Add role permissions
  Object.keys(rolePermissions).forEach(resource => {
    effectivePermissions[resource] = [...rolePermissions[resource]];
  });

  // Add custom permissions
  if (user.permissions && Array.isArray(user.permissions)) {
    user.permissions.forEach(permission => {
      if (!effectivePermissions[permission.resource]) {
        effectivePermissions[permission.resource] = [];
      }
      effectivePermissions[permission.resource] = [
        ...new Set([...effectivePermissions[permission.resource], ...permission.actions])
      ];
    });
  }

  await logSecurityEvent(req, 'permission_inquiry', `Retrieved permissions for user ${user.username}`, req.user._id, true);

  res.json({
    success: true,
    data: {
      userId: user._id,
      username: user.username,
      role: user.role,
      rolePermissions,
      customPermissions: user.permissions,
      effectivePermissions
    }
  });
}));

// Bulk role assignment
router.post('/bulk-assign', requirePermission('roles', 'manage'), sensitiveOperationLimiter, [
  body('userIds').isArray({ min: 1 }).withMessage('User IDs array is required'),
  body('role').isIn(['user', 'admin', 'manager', 'viewer']).withMessage('Invalid role')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { userIds, role } = req.body;

  const users = await User.find({ _id: { $in: userIds } });
  if (users.length !== userIds.length) {
    return res.status(400).json({
      success: false,
      message: 'Some users not found'
    });
  }

  const updates = [];
  for (const user of users) {
    const oldRole = user.role;
    user.role = role;
    await user.save();
    
    updates.push({
      userId: user._id,
      username: user.username,
      oldRole,
      newRole: role
    });
  }

  await logSecurityEvent(
    req, 
    'bulk_role_assignment', 
    `Bulk role assignment to ${role} for ${users.length} users`,
    req.user._id, 
    true
  );

  res.json({
    success: true,
    message: `${users.length} users updated to ${role} role`,
    data: {
      updatedUsers: updates
    }
  });
}));

module.exports = router;
