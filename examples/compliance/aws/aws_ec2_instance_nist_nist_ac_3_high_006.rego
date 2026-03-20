package crowdstrike

# EC2 Access Enforcement
# Framework: NIST 800-53 AC-3 (Access Enforcement)
# Control ID: NIST-AC-3
# Severity: HIGH
# Description: EC2 instances should enforce approved authorizations for logical access

default result := "fail"

# Skip non-AWS::EC2::Instance resources
result = "skip" if {
    input.resource_type != "AWS::EC2::Instance"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.configuration.iamInstanceProfile
}

result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.configuration.iamInstanceProfile
    count(input.configuration.iamInstanceProfile) > 0
}
