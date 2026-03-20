package crowdstrike

# Advanced GCP Compute Instance Security Policy
# Comprehensive security checks for GCP compute instances including service accounts, metadata, and network

default result := "fail"

# Skip non-GCP Compute instances
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Instance"
}

# Helper function to check service account security
secure_service_account(instance) if {
    instance.configuration.serviceAccounts[_].email != "default"
    count(instance.configuration.serviceAccounts[_].scopes) > 0
    not "https://www.googleapis.com/auth/cloud-platform" in instance.configuration.serviceAccounts[_].scopes
}

# Helper function to check metadata security
secure_metadata(instance) if {
    instance.configuration.metadata.items[_].key == "block-project-ssh-keys"
    instance.configuration.metadata.items[_].value == "true"
}

# Helper function to check OS Login
os_login_enabled(instance) if {
    instance.configuration.metadata.items[_].key == "enable-oslogin"
    instance.configuration.metadata.items[_].value == "TRUE"
}

# Helper function to check shielded VM
shielded_vm_enabled(instance) if {
    instance.configuration.shieldedInstanceConfig.enableSecureBoot == true
    instance.configuration.shieldedInstanceConfig.enableVtpm == true
    instance.configuration.shieldedInstanceConfig.enableIntegrityMonitoring == true
}

# Pass if all security requirements are met
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    secure_service_account(input)
    secure_metadata(input)
    os_login_enabled(input)
    shielded_vm_enabled(input)
    not input.configuration.canIpForward
}

# Provide specific failure reasons
violation contains msg if {
    input.resource_type == "compute.googleapis.com/Instance"
    not secure_service_account(input)
    msg := "Default service account or overprivileged scopes detected"
}

violation contains msg if {
    input.resource_type == "compute.googleapis.com/Instance"
    not secure_metadata(input)
    msg := "SSH keys not properly restricted"
}

violation contains msg if {
    input.resource_type == "compute.googleapis.com/Instance"
    not shielded_vm_enabled(input)
    msg := "Shielded VM features not fully enabled"
}