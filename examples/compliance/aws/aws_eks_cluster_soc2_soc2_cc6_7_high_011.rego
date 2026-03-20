package crowdstrike

# EKS Data Transmission Security
# Framework: SOC2 CC6.7 (System Operations)
# Control ID: SOC2-CC6.7
# Severity: HIGH
# Description: EKS clusters should secure data transmission

default result := "fail"

# Skip non-AWS::EKS::Cluster resources
result = "skip" if {
    input.resource_type != "AWS::EKS::Cluster"
}

# Pass if logging/monitoring is enabled
result = "pass" if {
    input.resource_type == "AWS::EKS::Cluster"
    input.configuration.logging.clusterLogging
    some log in input.configuration.logging.clusterLogging
    log.enabled == true
}
