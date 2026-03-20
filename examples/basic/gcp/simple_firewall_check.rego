package crowdstrike

# Simple GCP Firewall Rule Check
# Description: Basic example to check GCP firewall rules

default result := "fail"

# Skip non-GCP Firewall resources
result = "skip" if {
    input.resource_type != "compute.googleapis.com/Firewall"
}

# Pass if firewall rule is not too permissive
result = "pass" if {
    input.resource_type == "compute.googleapis.com/Firewall"
    not input.configuration.sourceRanges[_] == "0.0.0.0/0"
}