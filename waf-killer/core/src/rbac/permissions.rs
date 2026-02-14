use crate::rbac::roles::Role;
pub use crate::rbac::roles::Permission;

// Helper trait or struct if we need more complex logic in future
// For now, it mainly re-exports or simplifies access
pub trait CheckPermission {
    fn has_permission(&self, permission: Permission) -> bool;
}

impl CheckPermission for Role {
    fn has_permission(&self, permission: Permission) -> bool {
        self.has_permission(permission)
    }
}
