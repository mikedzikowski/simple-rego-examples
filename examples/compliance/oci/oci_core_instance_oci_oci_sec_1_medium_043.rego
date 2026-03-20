package crowdstrike

# Ensure Instance In-Transit Encryption
# Framework: OCI Security Best Practices
# Control ID: OCI-SEC-1
# Severity: MEDIUM
# Description: Instances should have in-transit encryption enabled

default result := "fail"

# Skip non-OCI::Core::Instance resources
result = "skip" if {
    input.resource_type != "OCI::Core::Instance"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "OCI::Core::Instance"
    input.configuration.launchOptions.isPvEncryptionInTransitEnabled == true
}
