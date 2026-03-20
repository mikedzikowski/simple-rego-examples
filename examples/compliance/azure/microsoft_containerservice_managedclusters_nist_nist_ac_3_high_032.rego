package crowdstrike

# AKS Access Enforcement
# Framework: NIST 800-53 AC-3 (Access Enforcement)
# Control ID: NIST-AC-3
# Severity: HIGH
# Description: AKS clusters should enforce access controls

default result := "fail"

# Skip non-Microsoft.ContainerService/managedClusters resources
result = "skip" if {
    input.resource_type != "Microsoft.ContainerService/managedClusters"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.ContainerService/managedClusters"
    input.configuration.properties.enableRBAC == true
}
