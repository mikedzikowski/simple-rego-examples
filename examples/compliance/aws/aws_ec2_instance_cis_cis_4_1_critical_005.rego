package crowdstrike

# Ensure No Security Groups Allow SSH from 0.0.0.0/0
# Framework: CIS AWS Foundations Benchmark v1.4.0
# Control ID: CIS-4.1
# Severity: CRITICAL
# Description: Security groups should not allow unrestricted SSH access

default result := "fail"

# Skip non-AWS::EC2::Instance resources
result = "skip" if {
    input.resource_type != "AWS::EC2::Instance"
}

# Pass if no security groups allow SSH from 0.0.0.0/0
result = "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.configuration.securityGroups
    not has_ssh_from_anywhere
}

# Helper rule to check for SSH access from anywhere
has_ssh_from_anywhere {
    some sg in input.configuration.securityGroups
    some rule in sg.ipPermissions
    rule.fromPort == 22
    rule.toPort == 22
    some range in rule.ipRanges
    range.cidrIp == "0.0.0.0/0"
}
