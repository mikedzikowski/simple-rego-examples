package crowdstrike

# EKS Transmission Confidentiality
# Framework: NIST 800-53 SC-8 (Transmission Confidentiality)
# Control ID: NIST-SC-8
# Severity: HIGH
# Description: EKS clusters should protect transmission confidentiality

default result := "fail"

# Skip non-AWS::EKS::Cluster resources
result = "skip" if {
    input.resource_type != "AWS::EKS::Cluster"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "AWS::EKS::Cluster"
    input.configuration.encryptionConfig
}

result = "pass" if {
    input.resource_type == "AWS::EKS::Cluster"
    input.configuration.encryptionConfig
    count(input.configuration.encryptionConfig) > 0
}
