package crowdstrike

# Storage Account Strong Cryptography
# Framework: PCI-DSS Requirement 4.1
# Control ID: PCI-DSS-4.1
# Severity: CRITICAL
# Description: Storage accounts should use strong cryptography for cardholder data

default result := "fail"

# Skip non-Microsoft.Storage/storageAccounts resources
result = "skip" if {
    input.resource_type != "Microsoft.Storage/storageAccounts"
}

# Pass if Microsoft Storage encryption is used
result = "pass" if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.properties.encryption.keySource == "Microsoft.Storage"
}
