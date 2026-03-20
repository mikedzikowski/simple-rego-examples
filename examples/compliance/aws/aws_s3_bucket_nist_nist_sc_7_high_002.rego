package crowdstrike

# S3 Boundary Protection
# Framework: NIST 800-53 SC-7 (Boundary Protection)
# Control ID: NIST-SC-7
# Severity: HIGH
# Description: S3 buckets should implement proper boundary protection

default result := "fail"

# Skip non-AWS::S3::Bucket resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.restrictPublicBuckets == true
}
