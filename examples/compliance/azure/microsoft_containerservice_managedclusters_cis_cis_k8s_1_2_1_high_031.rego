package crowdstrike

# Ensure AKS API Server Authorized Networks
# Framework: CIS Kubernetes Benchmark v1.6.0
# Control ID: CIS-K8S-1.2.1
# Severity: HIGH
# Description: AKS clusters should restrict API server access to authorized networks

default result := "fail"

# Skip non-Microsoft.ContainerService/managedClusters resources
result = "skip" if {
    input.resource_type != "Microsoft.ContainerService/managedClusters"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "Microsoft.ContainerService/managedClusters"
    input.configuration.properties.apiServerAccessProfile.authorizedIPRanges
}

result = "pass" if {
    input.resource_type == "Microsoft.ContainerService/managedClusters"
    input.configuration.properties.apiServerAccessProfile.authorizedIPRanges
    count(input.configuration.properties.apiServerAccessProfile.authorizedIPRanges) > 0
}
