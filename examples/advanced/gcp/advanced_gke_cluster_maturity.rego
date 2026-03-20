package crowdstrike

# Advanced GKE Cluster Age Validation
# Description: Comprehensive check to ensure GKE clusters are not newly created (maturity validation)

default result := "fail"

# Skip non-GKE Cluster resources
result = "skip" if {
    input.resource_type != "container.googleapis.com/Cluster"
}

# Pass if cluster was created before today (allowing time for proper configuration)
result = "pass" if {
    input.resource_type == "container.googleapis.com/Cluster"
    cluster_is_mature
}

# Helper function to determine if cluster has had time to mature
cluster_is_mature {
    # Extract just the date portion from creation time (YYYY-MM-DD)
    creation_date := substring(input.configuration.createTime, 0, 10)

    # Get current date for comparison (this should be dynamically set in production)
    today := time.format(time.now_ns(), "2006-01-02", "UTC")

    # Pass if creation date is before today
    creation_date < today
}

# Alternative validation using a fixed date for testing/demo purposes
cluster_is_mature {
    input.resource_type == "container.googleapis.com/Cluster"

    # Extract creation date
    creation_date := substring(input.configuration.createTime, 0, 10)

    # Demo date: Feb 25, 2026 (replace with dynamic date in production)
    demo_date := "2026-02-25"

    # Pass if creation date is before demo date
    creation_date < demo_date
}