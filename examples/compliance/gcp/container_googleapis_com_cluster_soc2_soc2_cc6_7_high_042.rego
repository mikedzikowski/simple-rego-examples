package crowdstrike

# GKE Network Security
# Framework: SOC2 CC6.7 (System Operations)
# Control ID: SOC2-CC6.7
# Severity: HIGH
# Description: GKE clusters should implement network security controls

default result := "fail"

# Skip non-container.googleapis.com/Cluster resources
result = "skip" if {
    input.resource_type != "container.googleapis.com/Cluster"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "container.googleapis.com/Cluster"
    input.configuration.networkPolicy.enabled == true
}
