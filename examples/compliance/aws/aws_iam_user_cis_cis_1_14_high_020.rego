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

# Main evaluation logic
result = "skip" if {
	input.resource_type != "AWS::IAM::User"
}

result = "pass" if {
	input.resource_type == "AWS::IAM::User"
	not input.enrichment_iam_credentialreport
}

result = "pass" if {
	input.resource_type == "AWS::IAM::User"
	input.enrichment_iam_credentialreport
	not input.enrichment_iam_credentialreport.configuration.accessKey1Active
}

result = "pass" if {
	input.resource_type == "AWS::IAM::User"
	input.enrichment_iam_credentialreport.configuration.accessKey1Active == true
	rotation_date := input.enrichment_iam_credentialreport.configuration.accessKey1LastRotated
	rotation_ns := time_parse_iso(rotation_date)
	days_old := days_between(today_ns, rotation_ns)
	days_old <= 180
}

result = "fail" if {
	input.resource_type == "AWS::IAM::User"
	input.enrichment_iam_credentialreport.configuration.accessKey1Active == true
	rotation_date := input.enrichment_iam_credentialreport.configuration.accessKey1LastRotated
	rotation_ns := time_parse_iso(rotation_date)
	days_old := days_between(today_ns, rotation_ns)
	days_old > 180
}