package crowdstrike

# Compute Instance Boundary Protection
# Framework: NIST 800-53 SC-7 (Boundary Protection)
# Control ID: NIST-SC-7
# Severity: HIGH
# Description: Compute instances should implement boundary protection

default result := "fail"

# Skip non-compute.googleapis.com/Instance resources
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Instance"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    input.configuration.metadata.items.enable-oslogin
}
