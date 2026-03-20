package crowdstrike

# OCI Instance Access Controls
# Framework: SOC2 CC6.1 (Logical Access Controls)
# Control ID: SOC2-CC6.1
# Severity: HIGH
# Description: OCI instances should implement access controls

default result := "fail"

# Skip non-OCI::Core::Instance resources
result = "skip" if {
    input.resource_type != "OCI::Core::Instance"
}

# Pass if SSH keys are configured (not passwords)
result = "pass" if {
    input.resource_type == "OCI::Core::Instance"
    input.configuration.metadata
    input.configuration.metadata.ssh_authorized_keys
}
