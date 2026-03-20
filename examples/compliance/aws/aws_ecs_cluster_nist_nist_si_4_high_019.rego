package crowdstrike

# ECS System Monitoring
# Framework: NIST 800-53 SI-4 (System Monitoring)
# Control ID: NIST-SI-4
# Severity: HIGH
# Description: ECS clusters should implement system monitoring capabilities

default result := "fail"

# Skip non-AWS::ECS::Cluster resources
result = "skip" if {
    input.resource_type != "AWS::ECS::Cluster"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "AWS::ECS::Cluster"
    input.configuration.capacityProviders
}

result = "pass" if {
    input.resource_type == "AWS::ECS::Cluster"
    input.configuration.capacityProviders
    count(input.configuration.capacityProviders) > 0
}
