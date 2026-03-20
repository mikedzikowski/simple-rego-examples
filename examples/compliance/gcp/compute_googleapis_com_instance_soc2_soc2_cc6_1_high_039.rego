package crowdstrike

# Compute Instance Access Controls
# Framework: SOC2 CC6.1 (Logical Access Controls)
# Control ID: SOC2-CC6.1
# Severity: HIGH
# Description: Compute instances should implement logical access controls

default result := "fail"

# Skip non-compute.googleapis.com/Instance resources
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Instance"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    input.configuration.shieldedInstanceConfig.enableSecureBoot == true
}
