package crowdstrike

# Simple GCP Instance Labels Check
# Description: Basic example to check if GCP instances have proper labels

default result := "fail"

# Skip non-GCP Compute instances
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Instance"
}

# Pass if instance has environment label
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    input.configuration.labels.environment
}

# Also pass if it has the legacy env tag
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Instance"
    input.configuration.labels.env
}