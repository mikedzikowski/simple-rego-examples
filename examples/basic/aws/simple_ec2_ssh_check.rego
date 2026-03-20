package crowdstrike

# Simple EC2 SSH Security Check
# Description: Basic example to check if EC2 instances avoid SSH access from anywhere

default result := "fail"

# Skip non-EC2 resources
result = "skip" if {
    input.resource_type != "AWS::EC2::Instance"
}

# Pass if no security groups allow SSH from 0.0.0.0/0
result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    security_group := input.configuration.securityGroups[_]
    security_group.ipPermissions[_].fromPort != 22
}