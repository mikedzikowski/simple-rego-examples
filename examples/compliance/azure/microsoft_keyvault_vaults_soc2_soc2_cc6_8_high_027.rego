package crowdstrike

# Key Vault Access Restrictions
# Framework: SOC2 CC6.8 (Logical Access)
# Control ID: SOC2-CC6.8
# Severity: HIGH
# Description: Key vaults should restrict logical access

default result := "fail"

# Skip non-Microsoft.KeyVault/vaults resources
result = "skip" if {
    input.resource_type != "Microsoft.KeyVault/vaults"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.KeyVault/vaults"
    input.configuration.properties.enableRbacAuthorization == true
}
