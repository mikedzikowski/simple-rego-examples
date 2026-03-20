package crowdstrike

# CloudTrail System Monitoring
# Framework: SOC2 CC7.2 (System Monitoring)
# Control ID: SOC2-CC7.2
# Severity: HIGH
# Description: CloudTrail should enable comprehensive system monitoring

default result := "fail"

# Skip non-AWS::CloudTrail::Trail resources
result = "skip" if {
    input.resource_type != "AWS::CloudTrail::Trail"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "AWS::CloudTrail::Trail"
    input.configuration.isMultiRegionTrail == true
}
