package crowdstrike

# EC2 Default Security Parameters
# Framework: PCI-DSS Requirement 2.1
# Control ID: PCI-DSS-2.1
# Severity: MEDIUM
# Description: EC2 instances should not use vendor default security parameters

default result := "fail"

# Skip non-AWS::EC2::Instance resources
result = "skip" if {
    input.resource_type != "AWS::EC2::Instance"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.configuration.keyName
}

result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.configuration.keyName
    count(input.configuration.keyName) > 0
}
