package crowdstrike

# Ensure No Security Groups Allow Unrestricted Access on Non-HTTP/HTTPS Ports
# Framework: CIS AWS Foundations Benchmark
# Control ID: CIS-4.2
# Severity: HIGH
# Description: Security groups should not allow unrestricted access (0.0.0.0/0 or ::/0) on ports other than HTTP (80) and HTTPS (443)

default result := "fail"

# Skip non-AWS::EC2::SecurityGroup resources
result = "skip" if {
    input.resource_type != "AWS::EC2::SecurityGroup"
}

# Pass if no security groups allow unrestricted access on non-HTTP/HTTPS ports
result = "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.configuration.ipPermissions
    not has_unrestricted_non_web_access
}

# Helper rule to check for unrestricted access on non-HTTP/HTTPS ports
has_unrestricted_non_web_access {
    some rule in input.configuration.ipPermissions

    # Check if rule allows unrestricted access (0.0.0.0/0 or ::/0)
    has_unrestricted_cidr(rule)

    # Check if port is not HTTP (80) or HTTPS (443)
    not is_web_port(rule)
}

# Helper to check if a rule has unrestricted CIDR blocks
has_unrestricted_cidr(rule) {
    some range in rule.ipRanges
    range.cidrIp in ["0.0.0.0/0"]
}

has_unrestricted_cidr(rule) {
    some range in rule.ipv6Ranges
    range.cidrIpv6 in ["::/0"]
}

# Helper to identify web ports (HTTP/HTTPS)
is_web_port(rule) {
    rule.fromPort == 80
    rule.toPort == 80
}

is_web_port(rule) {
    rule.fromPort == 443
    rule.toPort == 443
}

# Also allow port ranges that include web ports (less restrictive interpretation)
is_web_port(rule) {
    rule.fromPort <= 80
    rule.toPort >= 80
}

is_web_port(rule) {
    rule.fromPort <= 443
    rule.toPort >= 443
}