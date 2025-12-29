/**
 * RBAC Permissions Unit Tests
 *
 * Tests for role-based access control and permissions
 */

import {
  PERMISSIONS,
  ROLES,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRolePermissions,
  validatePermission
} from '../../../src/security/permissions';

describe('RBAC Permissions', () => {
  describe('Permission Definitions', () => {
    it('should have all required permission properties', () => {
      Object.values(PERMISSIONS).forEach(permission => {
        expect(permission).toHaveProperty('id');
        expect(permission).toHaveProperty('category');
        expect(permission).toHaveProperty('action');
        expect(permission).toHaveProperty('description');
        expect(permission).toHaveProperty('risk_level');
      });
    });

    it('should have consistent permission ID format', () => {
      Object.keys(PERMISSIONS).forEach(key => {
        expect(key).toMatch(/^[a-z_]+:[a-z_]+$/);
      });
    });

    it('should have valid risk levels', () => {
      const validRiskLevels = ['low', 'medium', 'high', 'critical'];

      Object.values(PERMISSIONS).forEach(permission => {
        expect(validRiskLevels).toContain(permission.risk_level);
      });
    });
  });

  describe('Role Definitions', () => {
    it('should define all required roles', () => {
      expect(ROLES).toHaveProperty('viewer');
      expect(ROLES).toHaveProperty('analyst');
      expect(ROLES).toHaveProperty('senior_analyst');
      expect(ROLES).toHaveProperty('admin');
    });

    it('should have permissions array for each role', () => {
      Object.values(ROLES).forEach(role => {
        expect(Array.isArray(role.permissions)).toBe(true);
        expect(role.permissions.length).toBeGreaterThan(0);
      });
    });

    it('should have escalating permissions across roles', () => {
      const viewerPerms = ROLES.viewer.permissions.length;
      const analystPerms = ROLES.analyst.permissions.length;
      const seniorAnalystPerms = ROLES.senior_analyst.permissions.length;
      const adminPerms = ROLES.admin.permissions.length;

      expect(analystPerms).toBeGreaterThan(viewerPerms);
      expect(seniorAnalystPerms).toBeGreaterThan(analystPerms);
      expect(adminPerms).toBeGreaterThan(seniorAnalystPerms);
    });
  });

  describe('hasPermission', () => {
    it('should return true when user has permission', () => {
      // Analyst should have scans:create permission
      expect(hasPermission('analyst', 'scans:create')).toBe(true);
    });

    it('should return false when user lacks permission', () => {
      // Viewer should not have scans:execute permission
      expect(hasPermission('viewer', 'scans:execute')).toBe(false);
    });

    it('should return true for admin on all permissions', () => {
      // Admin should have all permissions
      expect(hasPermission('admin', 'scans:create')).toBe(true);
      expect(hasPermission('admin', 'malware:execute')).toBe(true);
      expect(hasPermission('admin', 'admin:manage_users')).toBe(true);
    });

    it('should return false for invalid role', () => {
      expect(hasPermission('invalid_role', 'scans:read')).toBe(false);
    });

    it('should return false for invalid permission', () => {
      expect(hasPermission('analyst', 'invalid:permission')).toBe(false);
    });
  });

  describe('hasAnyPermission', () => {
    it('should return true when user has at least one permission', () => {
      // Viewer has scans:read but not scans:execute
      expect(hasAnyPermission('viewer', ['scans:read', 'scans:execute'])).toBe(true);
    });

    it('should return false when user has none of the permissions', () => {
      // Viewer has neither execute permission
      expect(hasAnyPermission('viewer', ['scans:execute', 'malware:execute'])).toBe(false);
    });

    it('should return true for admin with any permission set', () => {
      expect(hasAnyPermission('admin', ['scans:read', 'workflows:create'])).toBe(true);
    });

    it('should handle empty permission array', () => {
      expect(hasAnyPermission('analyst', [])).toBe(false);
    });
  });

  describe('hasAllPermissions', () => {
    it('should return true when user has all permissions', () => {
      // Analyst has both scans:read and scans:create
      expect(hasAllPermissions('analyst', ['scans:read', 'scans:create'])).toBe(true);
    });

    it('should return false when user lacks any permission', () => {
      // Viewer has scans:read but not scans:create
      expect(hasAllPermissions('viewer', ['scans:read', 'scans:create'])).toBe(false);
    });

    it('should return true for admin with all permissions', () => {
      expect(hasAllPermissions('admin', ['scans:read', 'workflows:create', 'admin:manage_users'])).toBe(true);
    });

    it('should handle empty permission array', () => {
      expect(hasAllPermissions('analyst', [])).toBe(true);
    });
  });

  describe('getRolePermissions', () => {
    it('should return all permissions for a role', () => {
      const permissions = getRolePermissions('analyst');

      expect(Array.isArray(permissions)).toBe(true);
      expect(permissions.length).toBeGreaterThan(0);
      expect(permissions).toContain('scans:read');
      expect(permissions).toContain('scans:create');
    });

    it('should return empty array for invalid role', () => {
      const permissions = getRolePermissions('invalid_role');

      expect(permissions).toEqual([]);
    });

    it('should return unique permissions', () => {
      const permissions = getRolePermissions('admin');
      const uniquePermissions = Array.from(new Set(permissions));

      expect(permissions.length).toBe(uniquePermissions.length);
    });
  });

  describe('validatePermission', () => {
    it('should validate existing permission', () => {
      expect(validatePermission('scans:read')).toBe(true);
      expect(validatePermission('malware:execute')).toBe(true);
      expect(validatePermission('admin:manage_users')).toBe(true);
    });

    it('should invalidate non-existing permission', () => {
      expect(validatePermission('invalid:permission')).toBe(false);
      expect(validatePermission('scans:nonexistent')).toBe(false);
    });

    it('should invalidate malformed permission strings', () => {
      expect(validatePermission('scans')).toBe(false);
      expect(validatePermission('scans:')).toBe(false);
      expect(validatePermission(':read')).toBe(false);
      expect(validatePermission('')).toBe(false);
    });
  });

  describe('Role Hierarchies', () => {
    it('viewer should have read-only permissions', () => {
      const viewerPerms = getRolePermissions('viewer');

      viewerPerms.forEach(perm => {
        expect(perm).toMatch(/:(read|list)$/);
      });
    });

    it('analyst should have create and execute permissions', () => {
      const analystPerms = getRolePermissions('analyst');

      expect(analystPerms).toContain('scans:create');
      expect(analystPerms).toContain('scans:execute');
      expect(analystPerms).toContain('malware:upload');
    });

    it('senior_analyst should have additional critical permissions', () => {
      expect(hasPermission('senior_analyst', 'malware:execute')).toBe(true);
      expect(hasPermission('senior_analyst', 'nexus:orchestrate')).toBe(true);
      expect(hasPermission('senior_analyst', 'workflows:approve')).toBe(true);
    });

    it('admin should have all permissions including user management', () => {
      expect(hasPermission('admin', 'admin:manage_users')).toBe(true);
      expect(hasPermission('admin', 'admin:manage_roles')).toBe(true);
      expect(hasPermission('admin', 'admin:view_audit_logs')).toBe(true);
    });
  });

  describe('Permission Categories', () => {
    it('should categorize scan permissions correctly', () => {
      const scanPerms = Object.values(PERMISSIONS).filter(
        p => p.category === 'scans'
      );

      expect(scanPerms.length).toBeGreaterThan(0);
      scanPerms.forEach(perm => {
        expect(perm.id).toMatch(/^scans:/);
      });
    });

    it('should categorize malware permissions correctly', () => {
      const malwarePerms = Object.values(PERMISSIONS).filter(
        p => p.category === 'malware'
      );

      expect(malwarePerms.length).toBeGreaterThan(0);
      malwarePerms.forEach(perm => {
        expect(perm.id).toMatch(/^malware:/);
      });
    });

    it('should categorize workflow permissions correctly', () => {
      const workflowPerms = Object.values(PERMISSIONS).filter(
        p => p.category === 'workflows'
      );

      expect(workflowPerms.length).toBeGreaterThan(0);
      workflowPerms.forEach(perm => {
        expect(perm.id).toMatch(/^workflows:/);
      });
    });
  });

  describe('Risk Level Assessment', () => {
    it('should mark execute operations as high or critical risk', () => {
      const executePerms = Object.values(PERMISSIONS).filter(
        p => p.action === 'execute'
      );

      executePerms.forEach(perm => {
        expect(['high', 'critical']).toContain(perm.risk_level);
      });
    });

    it('should mark read operations as low risk', () => {
      const readPerms = Object.values(PERMISSIONS).filter(
        p => p.action === 'read'
      );

      readPerms.forEach(perm => {
        expect(perm.risk_level).toBe('low');
      });
    });

    it('should mark delete operations as high or critical risk', () => {
      const deletePerms = Object.values(PERMISSIONS).filter(
        p => p.action === 'delete'
      );

      deletePerms.forEach(perm => {
        expect(['high', 'critical']).toContain(perm.risk_level);
      });
    });
  });

  describe('Permission Inheritance', () => {
    it('analyst should have all viewer permissions', () => {
      const viewerPerms = getRolePermissions('viewer');
      const analystPerms = getRolePermissions('analyst');

      viewerPerms.forEach(perm => {
        expect(analystPerms).toContain(perm);
      });
    });

    it('senior_analyst should have all analyst permissions', () => {
      const analystPerms = getRolePermissions('analyst');
      const seniorAnalystPerms = getRolePermissions('senior_analyst');

      analystPerms.forEach(perm => {
        expect(seniorAnalystPerms).toContain(perm);
      });
    });

    it('admin should have all senior_analyst permissions', () => {
      const seniorAnalystPerms = getRolePermissions('senior_analyst');
      const adminPerms = getRolePermissions('admin');

      seniorAnalystPerms.forEach(perm => {
        expect(adminPerms).toContain(perm);
      });
    });
  });

  describe('Special Cases', () => {
    it('should handle case-sensitive role names', () => {
      expect(hasPermission('Viewer', 'scans:read')).toBe(false);
      expect(hasPermission('ANALYST', 'scans:create')).toBe(false);
      expect(hasPermission('viewer', 'scans:read')).toBe(true);
    });

    it('should handle case-sensitive permission names', () => {
      expect(hasPermission('analyst', 'SCANS:READ')).toBe(false);
      expect(hasPermission('analyst', 'Scans:Create')).toBe(false);
      expect(hasPermission('analyst', 'scans:create')).toBe(true);
    });

    it('should handle whitespace in role names', () => {
      expect(hasPermission(' analyst ', 'scans:create')).toBe(false);
      expect(hasPermission('analyst ', 'scans:create')).toBe(false);
    });

    it('should handle whitespace in permission names', () => {
      expect(hasPermission('analyst', ' scans:create ')).toBe(false);
      expect(hasPermission('analyst', 'scans:create ')).toBe(false);
    });
  });
});
