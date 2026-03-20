package crowdstrike

# Ensure ECS Container Insights Enabled
# Framework: CIS Docker Benchmark v1.2.0
# Control ID: CIS-DOCKER-2.1
# Severity: MEDIUM
# Description: ECS clusters should have container insights enabled for monitoring

default result := "fail"

# Skip non-AWS::ECS::Cluster resources
result = "skip" if {
    input.resource_type != "AWS::ECS::Cluster"
}

# Pass if service is enabled
result = "pass" if {
    input.resource_type == "AWS::ECS::Cluster"
    input.configuration.settings.containerInsights == "ENABLED"
}

result = "pass" if {
    input.resource_type == "AWS::ECS::Cluster"
    input.configuration.settings.containerInsights == "enabled"
}
