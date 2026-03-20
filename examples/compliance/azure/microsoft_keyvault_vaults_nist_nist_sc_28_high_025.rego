package crowdstrike

# Key Vault Information Protection at Rest
# Framework: NIST 800-53 SC-28 (Protection of Information at Rest)
# Control ID: NIST-SC-28
# Severity: HIGH
# Description: Key vaults should protect cryptographic keys at rest

default result := "fail"

# Skip non-Microsoft.KeyVault/vaults resources
result = "skip" if {
    input.resource_type != "Microsoft.KeyVault/vaults"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.KeyVault/vaults"
    input.configuration.properties.enablePurgeProtection == true
}
