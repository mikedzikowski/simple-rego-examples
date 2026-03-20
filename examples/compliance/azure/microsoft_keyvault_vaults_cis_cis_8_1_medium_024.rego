package crowdstrike

# Ensure Key Vault Soft Delete is Enabled
# Framework: CIS Microsoft Azure Foundations Benchmark v1.3.0
# Control ID: CIS-8.1
# Severity: MEDIUM
# Description: Key vaults should have soft delete enabled

default result := "fail"

# Skip non-Microsoft.KeyVault/vaults resources
result = "skip" if {
    input.resource_type != "Microsoft.KeyVault/vaults"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.KeyVault/vaults"
    input.configuration.enableSoftDelete == true
}
