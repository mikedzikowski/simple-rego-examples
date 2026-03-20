package crowdstrike

# OCI Kubernetes Network Security
# Framework: SOC2 CC6.7 (System Operations)
# Control ID: SOC2-CC6.7
# Severity: HIGH
# Description: OCI Kubernetes should implement network security

default result := "fail"

# Skip non-OCI::ContainerEngine::Cluster resources
result = "skip" if {
    input.resource_type != "OCI::ContainerEngine::Cluster"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "OCI::ContainerEngine::Cluster"
    input.configuration.options.serviceLbSubnetIds
}

result = "pass" if {
    input.resource_type == "OCI::ContainerEngine::Cluster"
    input.configuration.options.serviceLbSubnetIds
    count(input.configuration.options.serviceLbSubnetIds) > 0
}
