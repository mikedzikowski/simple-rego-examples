package crowdstrike

# CloudTrail Event Logging
# Framework: NIST 800-53 AU-2 (Event Logging)
# Control ID: NIST-AU-2
# Severity: HIGH
# Description: CloudTrail should log security-relevant events

default result := "fail"

# Skip non-AWS::CloudTrail::Trail resources
result = "skip" if {
    input.resource_type != "AWS::CloudTrail::Trail"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "AWS::CloudTrail::Trail"
    input.configuration.includeGlobalServiceEvents == true
}
