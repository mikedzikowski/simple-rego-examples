package crowdstrike

# Storage Account Transmission Protection
# Framework: NIST 800-53 SC-8 (Transmission Confidentiality)
# Control ID: NIST-SC-8
# Severity: HIGH
# Description: Storage accounts should protect data in transmission

default result := "fail"

# Skip non-Microsoft.Storage/storageAccounts resources
result = "skip" if {
    input.resource_type != "Microsoft.Storage/storageAccounts"
}

# Pass if minimum TLS 1.2 is required
result = "pass" if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.properties.minimumTlsVersion == "TLS1_2"
}
