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

# Pass if API server is not publicly accessible (no public endpoint)
result = "pass" if {
    input.resource_type == "OCI::ContainerEngine::Cluster"
    not input.configuration.endpoints.publicEndpoint
}
