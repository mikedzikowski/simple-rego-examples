package crowdstrike

# Advanced Azure Storage Account Security Policy
# Comprehensive security checks for Azure Storage Accounts including encryption, network rules, and access policies

default result := "fail"

# Skip non-Azure Storage resources
result = "skip" if {
    input.resource_type != "Microsoft.Storage/storageAccounts"
}

# Helper function to check encryption status
is_encrypted(storage) if {
    storage.configuration.encryption.services.blob.enabled == true
    storage.configuration.encryption.services.file.enabled == true
}

# Helper function to check network access
has_network_restrictions(storage) if {
    storage.configuration.networkAcls.defaultAction == "Deny"
    count(storage.configuration.networkAcls.virtualNetworkRules) > 0
}

# Pass if all security requirements are met
result = "pass" if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.enableHttpsTrafficOnly == true
    is_encrypted(input)
    has_network_restrictions(input)
    input.configuration.allowBlobPublicAccess == false
}

# Provide specific failure reasons
violation contains msg if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.enableHttpsTrafficOnly != true
    msg := "HTTPS traffic not enforced"
}

violation contains msg if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    not is_encrypted(input)
    msg := "Storage encryption not properly configured"
}

violation contains msg if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    not has_network_restrictions(input)
    msg := "Network access restrictions not configured"
}