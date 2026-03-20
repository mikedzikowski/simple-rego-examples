package crowdstrike

# Enhanced AWS S3 Bucket Security Policy
# Comprehensive security checks for S3 buckets including encryption, public access, and versioning

default result := "fail"

# Skip non-S3 resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Comprehensive S3 security check - all conditions must be met
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"

    # Encryption must be enabled
    encryption_enabled

    # Public access must be blocked
    public_access_blocked

    # Must have required tags
    required_tags_present

    # Versioning should be enabled for data protection
    versioning_enabled
}

# Helper function: Check if encryption is properly configured
encryption_enabled {
    input.supplementaryConfiguration.BucketEncryptionConfiguration
    input.supplementaryConfiguration.BucketEncryptionConfiguration.rules
}

encryption_enabled {
    input.configuration.serverSideEncryptionConfiguration
    input.configuration.serverSideEncryptionConfiguration.rules[_].applyServerSideEncryptionByDefault
}

# Helper function: Verify public access is blocked
public_access_blocked {
    input.cloud_context.allows_public_access == false
}

public_access_blocked {
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration.blockPublicAcls == true
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration.ignorePublicAcls == true
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration.blockPublicPolicy == true
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration.restrictPublicBuckets == true
}

# Helper function: Check required tags are present
required_tags_present {
    input.tags
    required_tags := ["Environment", "Owner", "DataClassification", "BackupSchedule"]
    count([tag | tag := required_tags[_]; input.tags[tag]]) == count(required_tags)
}

# Helper function: Check if versioning is enabled
versioning_enabled {
    input.supplementaryConfiguration.BucketVersioningConfiguration
    input.supplementaryConfiguration.BucketVersioningConfiguration.status == "Enabled"
}