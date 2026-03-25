package crowdstrike

# IAM User Unrotated Access Keys Check (180 Days)
# Framework: CIS AWS Foundations Benchmark
# Control ID: CIS-1.14
# Severity: HIGH
# Description: Finds IOMs (indicators of misconfiguration) for IAM access keys that should be rotated every 180 days

# Helper to convert ISO timestamp to nanoseconds since epoch
time_parse_iso(date_string) := time.parse_rfc3339_ns(date_string)

# Calculate days between two dates
days_between(date1_ns, date2_ns) := abs(date1_ns - date2_ns) / (((24 * 60) * 60) * 1000000000)

# Today's date in nanoseconds (2026-03-25)
today_ns := time.parse_rfc3339_ns("2026-03-25T00:00:00Z")

# Main evaluation rule
default result := "fail"

result := "skip" if {
	input.resource_type != "AWS::IAM::User"
} else := "skip" if {
	input.resource_type == "AWS::IAM::User"
	should_skip
} else := "pass" if {
	input.resource_type == "AWS::IAM::User"
	should_pass
} else := "fail"

# Skip conditions: no credential report OR no active access keys
should_skip if {
	# No credential report exists
	not input.enrichment_iam_credentialreport
}

should_skip if {
	# Credential report exists but no active access keys
	input.enrichment_iam_credentialreport
	not input.enrichment_iam_credentialreport.configuration.accessKey1Active
	not input.enrichment_iam_credentialreport.configuration.accessKey2Active
}

# Pass conditions: all active access keys are within rotation window
should_pass if {
	# All active access keys are within 180-day rotation window
	input.enrichment_iam_credentialreport

	# At least one access key is active
	any_active_keys

	# Check accessKey1 if it's active
	key1_within_window

	# Check accessKey2 if it's active
	key2_within_window
}

# Helper: Check if any access keys are active
any_active_keys if {
	input.enrichment_iam_credentialreport.configuration.accessKey1Active == true
}

any_active_keys if {
	input.enrichment_iam_credentialreport.configuration.accessKey2Active == true
}

# Helper: Check if accessKey1 is within rotation window (or not active)
key1_within_window if {
	# Not active, so it passes
	not input.enrichment_iam_credentialreport.configuration.accessKey1Active
}

key1_within_window if {
	# Active and within rotation window
	input.enrichment_iam_credentialreport.configuration.accessKey1Active == true
	rotation_date := input.enrichment_iam_credentialreport.configuration.accessKey1LastRotated
	rotation_ns := time_parse_iso(rotation_date)
	days_old := days_between(today_ns, rotation_ns)
	days_old <= 180
}

# Helper: Check if accessKey2 is within rotation window (or not active)
key2_within_window if {
	# Not active, so it passes
	not input.enrichment_iam_credentialreport.configuration.accessKey2Active
}

key2_within_window if {
	# Active and within rotation window
	input.enrichment_iam_credentialreport.configuration.accessKey2Active == true
	rotation_date := input.enrichment_iam_credentialreport.configuration.accessKey2LastRotated
	rotation_ns := time_parse_iso(rotation_date)
	days_old := days_between(today_ns, rotation_ns)
	days_old <= 180
}