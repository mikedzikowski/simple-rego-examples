package crowdstrike

# Simple GCP Unmanaged Compute Check
# Description: Basic example to check if compute instances are managed by CrowdStrike Sensor

default result := "fail"

# Skip non-GCP Compute instances
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Instance"
}

# Pass if instance is managed by CrowdStrike Sensor
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    input.cloud_context.host.managed_by == "Sensor"
}