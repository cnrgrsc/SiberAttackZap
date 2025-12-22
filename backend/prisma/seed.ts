import { PrismaClient, PermissionCategory } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Seeding database...');

    // Create admin user
    const adminUser = await prisma.user.upsert({
        where: { username: 'caner.guresci' },
        update: {},
        create: {
            username: 'caner.guresci',
            firstName: 'Caner',
            lastName: 'Güreşci',
            email: 'caner.guresci@ibb.gov.tr',
            role: 'admin',
            department: 'IT Security',
            isActive: true,
            ldapVerified: true,
            createdBy: 'system',
        },
    });

    console.log('✅ Admin user created:', adminUser.username);

    // Create email preferences for admin
    const emailPref = await prisma.emailPreference.upsert({
        where: { userId: adminUser.id },
        update: {},
        create: {
            userId: adminUser.id,
            emailEnabled: true,
            scanStarted: true,
            scanCompleted: true,
            scanFailed: true,
            scanPaused: true,
            vulnCritical: true,
            vulnHigh: true,
            vulnMedium: true,
            vulnLow: false,
            vulnInfo: false,
            systemAlerts: true,
            weeklyReport: true,
            monthlyReport: true,
            dailyDigest: false,
        },
    });

    console.log('✅ Email preferences created for:', adminUser.username);

    // Create all system roles
    const roles = [
        {
            name: 'admin',
            displayName: 'Administrator',
            description: 'Full system access with all permissions',
            isSystem: true,
        },
        {
            name: 'security_manager',
            displayName: 'Security Manager',
            description: 'Manage security operations, scans, and reports',
            isSystem: true,
        },
        {
            name: 'security_analyst',
            displayName: 'Security Analyst',
            description: 'Analyze vulnerabilities and generate reports',
            isSystem: true,
        },
        {
            name: 'developer',
            displayName: 'Developer',
            description: 'Run scans and view results',
            isSystem: true,
        },
        {
            name: 'viewer',
            displayName: 'Viewer',
            description: 'Read-only access to scans and reports',
            isSystem: true,
        },
    ];

    const createdRoles: any = {};
    for (const roleData of roles) {
        const role = await prisma.role.upsert({
            where: { name: roleData.name },
            update: {},
            create: {
                ...roleData,
                createdBy: 'system',
            },
        });
        createdRoles[roleData.name] = role;
        console.log(`✅ Role created: ${role.displayName}`);
    }

    // Assign admin role to user
    const adminRole = createdRoles['admin'];
    const userRole = await prisma.userRole.upsert({
        where: {
            userId_roleId: {
                userId: adminUser.id,
                roleId: adminRole.id,
            },
        },
        update: {},
        create: {
            userId: adminUser.id,
            roleId: adminRole.id,
            assignedBy: 'system',
        },
    });

    console.log('✅ Admin role assigned to user');

    // Create all permissions (both lowercase and UPPERCASE for compatibility)
    const permissions = [
        // USER MANAGEMENT (lowercase)
        { name: 'user:read', category: PermissionCategory.USER_MANAGEMENT, displayName: 'View Users', description: 'View user list and details' },
        { name: 'user:create', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Create Users', description: 'Create new users' },
        { name: 'user:update', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Update Users', description: 'Update user information' },
        { name: 'user:delete', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Delete Users', description: 'Delete users' },

        // USER MANAGEMENT (UPPERCASE - Frontend compatibility)
        { name: 'USER_READ', category: PermissionCategory.USER_MANAGEMENT, displayName: 'View Users (Legacy)', description: 'View user list and details' },
        { name: 'USER_CREATE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Create Users (Legacy)', description: 'Create new users' },
        { name: 'USER_UPDATE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Update Users (Legacy)', description: 'Update user information' },
        { name: 'USER_DELETE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Delete Users (Legacy)', description: 'Delete users' },

        // ROLE MANAGEMENT (lowercase)
        { name: 'role:read', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'View Roles', description: 'View roles and permissions' },
        { name: 'role:create', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Create Roles', description: 'Create new roles' },
        { name: 'role:update', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Update Roles', description: 'Update role permissions' },
        { name: 'role:delete', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Delete Roles', description: 'Delete roles' },

        // ROLE MANAGEMENT (UPPERCASE)
        { name: 'ROLE_READ', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'View Roles (Legacy)', description: 'View roles and permissions' },
        { name: 'ROLE_CREATE', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Create Roles (Legacy)', description: 'Create new roles' },
        { name: 'ROLE_UPDATE', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Update Roles (Legacy)', description: 'Update role permissions' },
        { name: 'ROLE_DELETE', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Delete Roles (Legacy)', description: 'Delete roles' },

        // GROUP MANAGEMENT (lowercase)
        { name: 'group:read', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'View Groups', description: 'View groups and members' },
        { name: 'group:create', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Create Groups', description: 'Create new groups' },
        { name: 'group:update', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Update Groups', description: 'Update group settings' },
        { name: 'group:delete', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Delete Groups', description: 'Delete groups' },

        // GROUP MANAGEMENT (UPPERCASE)
        { name: 'GROUP_READ', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'View Groups (Legacy)', description: 'View groups and members' },
        { name: 'GROUP_CREATE', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Create Groups (Legacy)', description: 'Create new groups' },
        { name: 'GROUP_UPDATE', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Update Groups (Legacy)', description: 'Update group settings' },
        { name: 'GROUP_DELETE', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Delete Groups (Legacy)', description: 'Delete groups' },

        // SCAN MANAGEMENT (lowercase)
        { name: 'scan:read', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'View Scans', description: 'View scan results' },
        { name: 'scan:create', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Create Scans', description: 'Start new scans' },
        { name: 'scan:update', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Update Scans', description: 'Modify scan settings' },
        { name: 'scan:delete', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Delete Scans', description: 'Delete scan results' },

        // SCAN MANAGEMENT (UPPERCASE)
        { name: 'SCAN_WEB_CREATE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Create Web Scans', description: 'Create web security scans' },
        { name: 'SCAN_WEB_VIEW', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'View Web Scans', description: 'View web scan results' },
        { name: 'SCAN_MOBILE_CREATE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Create Mobile Scans', description: 'Create mobile app scans' },
        { name: 'SCAN_MOBILE_VIEW', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'View Mobile Scans', description: 'View mobile scan results' },
        { name: 'SCAN_HISTORY_VIEW_ALL', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'View All Scan History', description: 'View all users\' scan history' },

        // REPORT MANAGEMENT (lowercase)
        { name: 'report:read', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'View Reports', description: 'View scan reports' },
        { name: 'report:create', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Create Reports', description: 'Generate new reports' },
        { name: 'report:download', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Download Reports', description: 'Download report files' },

        // REPORT MANAGEMENT (UPPERCASE)
        { name: 'REPORT_VIEW_ALL', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'View All Reports', description: 'View all reports' },
        { name: 'REPORT_EMAIL_SEND', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Send Report Emails', description: 'Send reports via email' },

        // VULNERABILITY MANAGEMENT (lowercase)
        { name: 'vulnerability:read', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'View Vulnerabilities', description: 'View vulnerability details' },
        { name: 'vulnerability:update', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'Update Vulnerabilities', description: 'Update vulnerability status' },

        // EMAIL MANAGEMENT (lowercase)
        { name: 'email:read', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'View Email Logs', description: 'View email history' },
        { name: 'email:send', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'Send Emails', description: 'Send email notifications' },

        // EMAIL MANAGEMENT (UPPERCASE)
        { name: 'EMAIL_SEND_INDIVIDUAL', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'Send Individual Emails', description: 'Send individual email notifications' },

        // SYSTEM MANAGEMENT (lowercase)
        { name: 'system:config', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'System Configuration', description: 'Manage system settings' },
        { name: 'system:settings:view', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'View System Settings', description: 'View system configuration' },
        { name: 'system:settings:update', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'Update System Settings', description: 'Modify system configuration' },
        { name: 'system:logs', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'View System Logs', description: 'Access system logs' },
        { name: 'system:audit', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'View Audit Logs', description: 'View audit trail' },

        // SYSTEM MANAGEMENT (UPPERCASE)
        { name: 'SYSTEM_SETTINGS_VIEW', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'View System Settings (Legacy)', description: 'View system configuration' },
        { name: 'SYSTEM_SETTINGS_UPDATE', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'Update System Settings (Legacy)', description: 'Update system settings' },

        // API MANAGEMENT (lowercase)
        { name: 'api:read', category: PermissionCategory.API_MANAGEMENT, displayName: 'View API Keys', description: 'View API key list' },
        { name: 'api:create', category: PermissionCategory.API_MANAGEMENT, displayName: 'Create API Keys', description: 'Generate new API keys' },
        { name: 'api:delete', category: PermissionCategory.API_MANAGEMENT, displayName: 'Delete API Keys', description: 'Revoke API keys' },

        // DASHBOARD MANAGEMENT (lowercase)
        { name: 'dashboard:view', category: PermissionCategory.DASHBOARD_MANAGEMENT, displayName: 'View Dashboard', description: 'Access main dashboard' },
        { name: 'dashboard:analytics', category: PermissionCategory.DASHBOARD_MANAGEMENT, displayName: 'View Analytics', description: 'View analytics and statistics' },
    ];

    for (const perm of permissions) {
        const permission = await prisma.permission.upsert({
            where: { name: perm.name },
            update: {},
            create: perm,
        });

        // Assign ALL permissions to admin role
        await prisma.rolePermission.upsert({
            where: {
                roleId_permissionId: {
                    roleId: createdRoles['admin'].id,
                    permissionId: permission.id,
                },
            },
            update: {},
            create: {
                roleId: createdRoles['admin'].id,
                permissionId: permission.id,
                grantedBy: 'system',
            },
        });
    }

    console.log(`✅ ${permissions.length} permissions created and assigned to admin role`);

    // Assign permissions to Security Manager
    const securityManagerPermissions = [
        'user:read', 'user:create', 'user:update',
        'role:read', 'group:read', 'group:create', 'group:update',
        'scan:read', 'scan:create', 'scan:update', 'scan:delete',
        'report:read', 'report:create', 'report:download',
        'vulnerability:read', 'vulnerability:update',
        'email:read', 'email:send',
        'system:settings:view', 'system:logs',
        'dashboard:view', 'dashboard:analytics',
    ];

    for (const permName of securityManagerPermissions) {
        const permission = await prisma.permission.findUnique({ where: { name: permName } });
        if (permission) {
            await prisma.rolePermission.upsert({
                where: {
                    roleId_permissionId: {
                        roleId: createdRoles['security_manager'].id,
                        permissionId: permission.id,
                    },
                },
                update: {},
                create: {
                    roleId: createdRoles['security_manager'].id,
                    permissionId: permission.id,
                    grantedBy: 'system',
                },
            });
        }
    }
    console.log(`✅ ${securityManagerPermissions.length} permissions assigned to Security Manager`);

    // Assign permissions to Security Analyst
    const securityAnalystPermissions = [
        'user:read', 'role:read', 'group:read',
        'scan:read', 'scan:create', 'scan:update',
        'report:read', 'report:create', 'report:download',
        'vulnerability:read', 'vulnerability:update',
        'dashboard:view', 'dashboard:analytics',
    ];

    for (const permName of securityAnalystPermissions) {
        const permission = await prisma.permission.findUnique({ where: { name: permName } });
        if (permission) {
            await prisma.rolePermission.upsert({
                where: {
                    roleId_permissionId: {
                        roleId: createdRoles['security_analyst'].id,
                        permissionId: permission.id,
                    },
                },
                update: {},
                create: {
                    roleId: createdRoles['security_analyst'].id,
                    permissionId: permission.id,
                    grantedBy: 'system',
                },
            });
        }
    }
    console.log(`✅ ${securityAnalystPermissions.length} permissions assigned to Security Analyst`);

    // Assign permissions to Developer
    const developerPermissions = [
        'scan:read', 'scan:create',
        'report:read', 'report:download',
        'vulnerability:read',
        'dashboard:view',
    ];

    for (const permName of developerPermissions) {
        const permission = await prisma.permission.findUnique({ where: { name: permName } });
        if (permission) {
            await prisma.rolePermission.upsert({
                where: {
                    roleId_permissionId: {
                        roleId: createdRoles['developer'].id,
                        permissionId: permission.id,
                    },
                },
                update: {},
                create: {
                    roleId: createdRoles['developer'].id,
                    permissionId: permission.id,
                    grantedBy: 'system',
                },
            });
        }
    }
    console.log(`✅ ${developerPermissions.length} permissions assigned to Developer`);

    // Assign permissions to Viewer
    const viewerPermissions = [
        'scan:read',
        'report:read',
        'vulnerability:read',
        'dashboard:view',
    ];

    for (const permName of viewerPermissions) {
        const permission = await prisma.permission.findUnique({ where: { name: permName } });
        if (permission) {
            await prisma.rolePermission.upsert({
                where: {
                    roleId_permissionId: {
                        roleId: createdRoles['viewer'].id,
                        permissionId: permission.id,
                    },
                },
                update: {},
                create: {
                    roleId: createdRoles['viewer'].id,
                    permissionId: permission.id,
                    grantedBy: 'system',
                },
            });
        }
    }
    console.log(`✅ ${viewerPermissions.length} permissions assigned to Viewer`);

    console.log('\n🎉 Seeding completed successfully!\n');
    console.log('📋 Admin User Details:');
    console.log('   Username:', adminUser.username);
    console.log('   Email:', adminUser.email);
    console.log('   Role:', adminUser.role);
    console.log('   Active:', adminUser.isActive);
    console.log('\n🔐 You can now login with username: caner.guresci');
}

main()
    .catch((e) => {
        console.error('❌ Seeding failed:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
