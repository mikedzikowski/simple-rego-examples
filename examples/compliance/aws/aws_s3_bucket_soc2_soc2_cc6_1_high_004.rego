package crowdstrike

# S3 Logical Access Controls
# Framework: SOC2 CC6.1 (Logical Access Controls)
# Control ID: SOC2-CC6.1
# Severity: HIGH
# Description: S3 buckets should implement logical access controls

default result := "fail"

# Skip non-AWS::S3::Bucket resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Pass if security policy exists
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.supplementaryConfiguration.BucketPolicy
    input.supplementaryConfiguration.BucketPolicy != ""
    input.supplementaryConfiguration.BucketPolicy != null
}
