package crowdstrike

# Storage Account Data Transmission
# Framework: SOC2 CC6.7 (System Operations)
# Control ID: SOC2-CC6.7
# Severity: HIGH
# Description: Storage accounts should secure data transmission

default result := "fail"

# Skip non-Microsoft.Storage/storageAccounts resources
result = "skip" if {
    input.resource_type != "Microsoft.Storage/storageAccounts"
}

# Pass if network access is restricted (defaultAction Deny indicates restricted access)
result = "pass" if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.properties.networkAcls.defaultAction == "Deny"
}
