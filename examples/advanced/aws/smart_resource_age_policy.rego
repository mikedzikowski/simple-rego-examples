package crowdstrike

# Smart Resource Age-based Policy
# Flags resources older than specified thresholds based on resource type

default result := "pass"

# Resource age thresholds in days
critical_age := {
    "AWS::EC2::Instance": 90,
    "AWS::Lambda::Function": 180,
    "AWS::S3::Bucket": 365,
    "Microsoft.Compute/virtualMachines": 90,
    "compute.googleapis.com/Instance": 90
}

# Calculate resource age
resource_age_days := days_since_creation if {
    input.configuration.createTime
    creation_timestamp := time.parse_rfc3339_ns(input.configuration.createTime)
    now_timestamp := time.now_ns()
    days_since_creation := (now_timestamp - creation_timestamp) / (1000000000 * 60 * 60 * 24)
}

resource_age_days := days_since_creation if {
    input.configuration.creationTime
    creation_timestamp := time.parse_rfc3339_ns(input.configuration.creationTime)
    now_timestamp := time.now_ns()
    days_since_creation := (now_timestamp - creation_timestamp) / (1000000000 * 60 * 60 * 24)
}

resource_age_days := days_since_creation if {
    input.first_seen
    creation_timestamp := time.parse_rfc3339_ns(input.first_seen)
    now_timestamp := time.now_ns()
    days_since_creation := (now_timestamp - creation_timestamp) / (1000000000 * 60 * 60 * 24)
}

# Fail if resource is older than threshold
result = "fail" if {
    threshold := critical_age[input.resource_type]
    resource_age_days > threshold

    # Allow exemption for production resources with proper lifecycle tags
    not lifecycle_exemption
}

# Skip resource types we don't have age policies for
result = "skip" if {
    not critical_age[input.resource_type]
}

# Lifecycle exemption logic
lifecycle_exemption {
    input.tags.Environment == "production"
    input.tags.Lifecycle == "long-term"
    input.tags.BusinessJustification
}

lifecycle_exemption {
    input.tags.ResourceStatus == "critical"
    input.tags.MaintenanceWindow
}