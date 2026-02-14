use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Owner,            // Full access, billing
    Admin,            // Manage team, settings
    SecurityEngineer, // Manage rules, policies
    Analyst,          // View data, comment
    Viewer,           // Read-only
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Owner => write!(f, "Owner"),
            Role::Admin => write!(f, "Admin"),
            Role::SecurityEngineer => write!(f, "SecurityEngineer"),
            Role::Analyst => write!(f, "Analyst"),
            Role::Viewer => write!(f, "Viewer"),
        }
    }
}

// For SQLx parsing from string
impl std::str::FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Owner" => Ok(Role::Owner),
            "Admin" => Ok(Role::Admin),
            "SecurityEngineer" => Ok(Role::SecurityEngineer),
            "Analyst" => Ok(Role::Analyst),
            "Viewer" => Ok(Role::Viewer),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    // Tenant management
    ManageTenant,
    ViewBilling,
    ManageBilling,
    
    // Team management
    InviteMembers,
    RemoveMembers,
    ChangeRoles,
    
    // Policy management
    ViewPolicies,
    EditPolicies,
    DeployPolicies,
    
    // Rules
    ViewRules,
    EditRules,
    EnableDisableRules,
    
    // Virtual patches
    ViewPatches,
    CreatePatches,
    ActivatePatches,
    
    // Data
    ViewRequests,
    ViewSensitiveData,  // PII in logs
    ExportData,
    
    // Collaboration
    Comment,
    AssignTasks,
    
    // Audit
    ViewAuditLog,
}

impl Role {
    pub fn has_permission(&self, permission: Permission) -> bool {
        use Permission::*;
        
        match self {
            Role::Owner => true,  // Owner has all permissions
            
            Role::Admin => !matches!(permission, 
                ManageBilling  // Only owner can manage billing
            ),
            
            Role::SecurityEngineer => matches!(permission,
                ViewPolicies | EditPolicies | DeployPolicies |
                ViewRules | EditRules | EnableDisableRules |
                ViewPatches | CreatePatches | ActivatePatches |
                ViewRequests | Comment | AssignTasks |
                ViewAuditLog
            ),
            
            Role::Analyst => matches!(permission,
                ViewPolicies | ViewRules | ViewPatches |
                ViewRequests | Comment | ViewAuditLog
            ),
            
            Role::Viewer => matches!(permission,
                ViewPolicies | ViewRules | ViewPatches | ViewRequests
            ),
        }
    }
    
    pub fn all_permissions(&self) -> Vec<Permission> {
        Permission::all()
            .into_iter()
            .filter(|p| self.has_permission(*p))
            .collect()
    }
}

impl Permission {
    pub fn all() -> Vec<Self> {
        vec![
            Permission::ManageTenant,
            Permission::ViewBilling,
            Permission::ManageBilling,
            Permission::InviteMembers,
            Permission::RemoveMembers,
            Permission::ChangeRoles,
            Permission::ViewPolicies,
            Permission::EditPolicies,
            Permission::DeployPolicies,
            Permission::ViewRules,
            Permission::EditRules,
            Permission::EnableDisableRules,
            Permission::ViewPatches,
            Permission::CreatePatches,
            Permission::ActivatePatches,
            Permission::ViewRequests,
            Permission::ViewSensitiveData,
            Permission::ExportData,
            Permission::Comment,
            Permission::AssignTasks,
            Permission::ViewAuditLog,
        ]
    }
}
