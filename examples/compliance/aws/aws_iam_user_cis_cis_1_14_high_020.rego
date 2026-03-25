package crowdstrike

# IAM User Unrotated Access Keys Check (180 Days)
# Framework: CIS AWS Foundations Benchmark
# Control ID: CIS-1.14
# Severity: HIGH
# Description: IAM access keys should be rotated every 180 days

# Helper to convert ISO timestamp to nanoseconds since epoch
time_parse_iso(date_string) := time.parse_rfc3339_ns(date_string)

# Calculate days between two dates
days_between(date1_ns, date2_ns) := abs(date1_ns - date2_ns) / (((24 * 60) * 60) * 1000000000)

# Today's date in nanoseconds (2026-03-25)
today_ns := time.parse_rfc3339_ns("2026-03-25T00:00:00Z")

default result := "fail"

# Skip non-AWS::IAM::User resources
result = "skip" {
	input.resource_type != "AWS::IAM::User"
}

# Pass if no credential report exists
result = "pass" {
	input.resource_type == "AWS::IAM::User"
	not input.enrichment_iam_credentialreport
}

# Pass if access key is not active or doesn't exist
result = "pass" {
	input.resource_type == "AWS::IAM::User"
	input.enrichment_iam_credentialreport
	not input.enrichment_iam_credentialreport.configuration.accessKey1Active
}

# Pass if access key was rotated within 180 days
result = "pass" {
	input.resource_type == "AWS::IAM::User"
	input.enrichment_iam_credentialreport.configuration.accessKey1Active == true
	rotation_date := input.enrichment_iam_credentialreport.configuration.accessKey1LastRotated
	rotation_ns := time_parse_iso(rotation_date)
	days_old := days_between(today_ns, rotation_ns)
	days_old <= 180
}