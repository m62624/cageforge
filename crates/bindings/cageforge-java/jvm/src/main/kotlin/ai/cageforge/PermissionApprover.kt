package ai.cageforge

/** Trusted host capability that issues an opaque grant for a request. */
class PermissionApprover {
    /** Approves the complete request with the default session lifetime. */
    fun approve(request: PermissionRequest): PermissionGrant = request.approve()
}
