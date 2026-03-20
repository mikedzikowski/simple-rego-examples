package crowdstrike

# Ensure GKE Private Cluster
# Framework: CIS Kubernetes Benchmark v1.6.0
# Control ID: CIS-K8S-1.2.1
# Severity: HIGH
# Description: GKE clusters should use private nodes

default result := "fail"

# Skip non-container.googleapis.com/Cluster resources
result = "skip" if {
    input.resource_type != "container.googleapis.com/Cluster"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "container.googleapis.com/Cluster"
    input.configuration.privateClusterConfig.enablePrivateNodes == true
}
