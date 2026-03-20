package crowdstrike

# S3 Network Access Restrictions
# Framework: PCI-DSS Requirement 1.3
# Control ID: PCI-DSS-1.3
# Severity: CRITICAL
# Description: S3 buckets storing cardholder data should restrict network access

default result := "fail"

# Skip non-AWS::S3::Bucket resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.ignorePublicAcls == true
}
