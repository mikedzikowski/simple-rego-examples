package crowdstrike

# Simple Azure Key Vault Access Check
# Description: Basic example to check Azure Key Vault access policies

default result := "fail"

# Skip non-Key Vault resources
result = "skip" if {
    input.resource_type != "Microsoft.KeyVault/vaults"
}

# Pass if access policies exist
result = "pass" if {
    input.resource_type == "Microsoft.KeyVault/vaults"
    count(input.configuration.properties.accessPolicies) > 0
}