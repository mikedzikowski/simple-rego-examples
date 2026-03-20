package crowdstrike

# Key Vault Cryptographic Key Management
# Framework: PCI-DSS Requirement 3.6
# Control ID: PCI-DSS-3.6
# Severity: CRITICAL
# Description: Key vaults should implement secure cryptographic key management

default result := "fail"

# Skip non-Microsoft.KeyVault/vaults resources
result = "skip" if {
    input.resource_type != "Microsoft.KeyVault/vaults"
}

# Pass if access is explicitly denied
result = "pass" if {
    input.resource_type == "Microsoft.KeyVault/vaults"
    input.configuration.properties.networkAcls.defaultAction == "Deny"
}
