package crowdstrike

# Ensure CloudTrail Log File Integrity Validation
# Framework: CIS AWS Foundations Benchmark v1.4.0
# Control ID: CIS-3.1
# Severity: MEDIUM
# Description: CloudTrail should have log file integrity validation enabled

default result := "fail"

# Skip non-AWS::CloudTrail::Trail resources
result = "skip" if {
    input.resource_type != "AWS::CloudTrail::Trail"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "AWS::CloudTrail::Trail"
    input.configuration.enableLogFileValidation == true
}
