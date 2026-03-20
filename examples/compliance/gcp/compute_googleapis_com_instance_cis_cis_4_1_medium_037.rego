package crowdstrike

# Ensure Compute Instance Does Not Have Public IP
# Framework: CIS Google Cloud Platform Foundation Benchmark v1.2.0
# Control ID: CIS-4.1
# Severity: MEDIUM
# Description: Compute instances should not have external IP addresses

default result := "fail"

# Skip non-compute.googleapis.com/Instance resources
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Instance"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    input.configuration.networkInterfaces.accessConfigs
}
