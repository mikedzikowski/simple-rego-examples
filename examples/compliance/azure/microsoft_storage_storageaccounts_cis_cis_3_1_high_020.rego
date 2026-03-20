package crowdstrike

# Ensure Storage Account Secure Transfer Required
# Framework: CIS Microsoft Azure Foundations Benchmark v1.3.0
# Control ID: CIS-3.1
# Severity: HIGH
# Description: Storage accounts should enforce HTTPS-only connections

default result := "fail"

# Skip non-Microsoft.Storage/storageAccounts resources
result = "skip" if {
    input.resource_type != "Microsoft.Storage/storageAccounts"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.enableHttpsTrafficOnly == true
}
