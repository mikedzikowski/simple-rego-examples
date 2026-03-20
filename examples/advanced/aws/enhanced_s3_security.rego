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
    input.configuration.encryptionConfiguration
    input.configuration.encryptionConfiguration.encryptionType
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
    input.configuration.publicAccessBlockConfiguration
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true
    input.configuration.publicAccessBlockConfiguration.ignorePublicAcls == true
    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == true
    input.configuration.publicAccessBlockConfiguration.restrictPublicBuckets == true
}

# Helper function: Check required tags are present
required_tags_present {
    input.tags
    required_tags := ["Environment", "Owner", "DataClassification", "BackupSchedule"]
    count([tag | tag := required_tags[_]; input.tags[tag]]) == count(required_tags)
}

# Helper function: Check if versioning is enabled
versioning_enabled {
    input.configuration.versioningConfiguration
    input.configuration.versioningConfiguration.status == "Enabled"
}