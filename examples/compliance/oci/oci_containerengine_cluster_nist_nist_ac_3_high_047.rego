package crowdstrike

# OCI Kubernetes Access Enforcement
# Framework: NIST 800-53 AC-3 (Access Enforcement)
# Control ID: NIST-AC-3
# Severity: HIGH
# Description: OCI Kubernetes clusters should enforce access controls

default result := "fail"

# Skip non-OCI::ContainerEngine::Cluster resources
result = "skip" if {
    input.resource_type != "OCI::ContainerEngine::Cluster"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "OCI::ContainerEngine::Cluster"
    input.configuration.options.kubernetesNetworkConfig.podsCidr
}

result = "pass" if {
    input.resource_type == "OCI::ContainerEngine::Cluster"
    input.configuration.options.kubernetesNetworkConfig.podsCidr
    count(input.configuration.options.kubernetesNetworkConfig.podsCidr) > 0
}
