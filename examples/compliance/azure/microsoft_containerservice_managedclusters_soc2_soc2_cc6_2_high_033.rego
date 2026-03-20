package crowdstrike

# AKS Privileged Access
# Framework: SOC2 CC6.2 (Privileged Access)
# Control ID: SOC2-CC6.2
# Severity: HIGH
# Description: AKS clusters should manage privileged access

default result := "fail"

# Skip non-Microsoft.ContainerService/managedClusters resources
result = "skip" if {
    input.resource_type != "Microsoft.ContainerService/managedClusters"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.ContainerService/managedClusters"
    input.configuration.aadProfile.managed == true
}
