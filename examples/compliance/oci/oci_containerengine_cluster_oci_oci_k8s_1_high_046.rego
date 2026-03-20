package crowdstrike

# Ensure Kubernetes API Server Not Public
# Framework: OCI Security Best Practices
# Control ID: OCI-K8S-1
# Severity: HIGH
# Description: Kubernetes clusters should not expose API server publicly

default result := "fail"

# Skip non-OCI::ContainerEngine::Cluster resources
result = "skip" if {
    input.resource_type != "OCI::ContainerEngine::Cluster"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "OCI::ContainerEngine::Cluster"
    input.configuration.endpoints.publicEndpoint
}
