package crowdstrike

# EC2 Privileged Access Management
# Framework: SOC2 CC6.2 (Privileged Access)
# Control ID: SOC2-CC6.2
# Severity: HIGH
# Description: EC2 instances should implement privileged access management

default result := "fail"

# Skip non-AWS::EC2::Instance resources
result = "skip" if {
    input.resource_type != "AWS::EC2::Instance"
}

# Pass if security setting is set to required
result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.configuration.metadataOptions.httpTokens == "required"
}
