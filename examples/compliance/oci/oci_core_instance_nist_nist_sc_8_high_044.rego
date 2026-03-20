package crowdstrike

# OCI Instance Transmission Protection
# Framework: NIST 800-53 SC-8 (Transmission Confidentiality)
# Control ID: NIST-SC-8
# Severity: HIGH
# Description: OCI instances should protect data transmission

default result := "fail"

# Skip non-OCI::Core::Instance resources
result = "skip" if {
    input.resource_type != "OCI::Core::Instance"
}

# Pass if setting is disabled for security
result = "pass" if {
    input.resource_type == "OCI::Core::Instance"
    input.configuration.agentConfig.isMonitoringDisabled == false
}
