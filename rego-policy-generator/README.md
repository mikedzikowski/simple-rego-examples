# Rego Policy Generator 🤖

A containerized tool for generating, validating, and testing custom Rego security policies with built-in AI assistance.

## Features

🎯 **Interactive Policy Generation** - Guided CLI interface for building policies
✅ **Multi-Layer Validation** - Syntax, structure, logic, and security validation
🧪 **Automated Testing** - Generate and run test scenarios
📊 **Security Analysis** - Score policies and get recommendations
🌐 **REST API** - Web interface for integration
📚 **Template Library** - Pre-built patterns for AWS, Azure, GCP, OCI
🔧 **OPA Integration** - Built-in OPA engine for validation

## Quick Start

### Using Docker

```bash
# Pull the container
docker pull your-registry/rego-policy-generator:latest

# Run interactive mode
docker run -it --rm rego-policy-generator interactive

# Run API server
docker run -p 8080:8080 rego-policy-generator
```

### Building Locally

```bash
# Clone and build
git clone <repo-url>
cd rego-policy-generator
docker build -t rego-policy-generator .

# Run
docker run -it --rm rego-policy-generator interactive
```

## Usage Examples

### 1. Interactive Policy Creation

```bash
$ docker run -it --rm rego-policy-generator interactive

🤖 Welcome to the Rego Policy Generator!
Let's create a custom security policy together.

Policy Title [Custom Security Policy]: No SSH from Internet
Framework [CIS Security Benchmark]: CIS AWS Foundations
Control ID [CIS-X.X]: CIS-4.1
Severity (LOW/MEDIUM/HIGH/CRITICAL) [HIGH]: CRITICAL
Description: Ensure security groups don't allow SSH from 0.0.0.0/0
Cloud Provider (aws/azure/gcp/oci) [aws]: aws
Resource Type: AWS::EC2::SecurityGroup

🔨 Generating policy...
🔍 Validating syntax...
✅ Syntax validation passed!
🧪 Generating test scenarios...

📄 Policy Preview:
--------------------------------------------------
package crowdstrike

# No SSH from Internet
# Framework: CIS AWS Foundations
# Control ID: CIS-4.1
# Severity: CRITICAL
# Description: Ensure security groups don't allow SSH from 0.0.0.0/0
...
--------------------------------------------------

💾 Save this policy? [Y/n]: y
✅ Policy saved to: aws_ec2_securitygroup_cis_4_1.rego
✅ Test scenarios saved to: aws_ec2_securitygroup_cis_4_1_tests.json
🚀 Ready to use in your compliance scanning!
```

### 2. API Usage

```bash
# Start API server
docker run -p 8080:8080 rego-policy-generator

# Generate policy via API
curl -X POST "http://localhost:8080/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "No RDP Access",
    "control_id": "CIS-4.2",
    "severity": "HIGH",
    "description": "Ensure no RDP access from internet",
    "resource_type": "AWS::EC2::SecurityGroup"
  }'

# Validate existing policy
curl -X POST "http://localhost:8080/validate" \
  -H "Content-Type: application/json" \
  -d '{"policy_content": "package crowdstrike\n..."}'
```

### 3. CLI Commands

```bash
# Generate from config file
docker run -v $(pwd):/workspace rego-policy-generator generate -c /workspace/config.yaml -o /workspace/policy.rego

# Validate policy file
docker run -v $(pwd):/workspace rego-policy-generator validate /workspace/policy.rego

# Get help
docker run --rm rego-policy-generator --help
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/generate` | POST | Generate policy from config |
| `/validate` | POST | Validate policy syntax & structure |
| `/test` | POST | Run test scenarios against policy |
| `/analyze` | POST | Security analysis and scoring |
| `/templates` | GET | Get available templates |
| `/examples` | GET | Get example policies |

## Configuration Format

### YAML Configuration
```yaml
title: "Custom Security Policy"
framework: "CIS AWS Foundations"
control_id: "CIS-4.1"
severity: "HIGH"
description: "Policy description"
resource_type: "AWS::EC2::SecurityGroup"
conditions:
  - "some rule in input.configuration.ipPermissions"
  - "rule.fromPort == 22"
  - "has_unrestricted_access(rule)"
```

### JSON Configuration
```json
{
  "title": "Custom Security Policy",
  "framework": "CIS AWS Foundations",
  "control_id": "CIS-4.1",
  "severity": "HIGH",
  "description": "Policy description",
  "resource_type": "AWS::EC2::SecurityGroup",
  "conditions": [
    "some rule in input.configuration.ipPermissions",
    "rule.fromPort == 22",
    "has_unrestricted_access(rule)"
  ]
}
```

## Validation Layers

The tool performs 4-layer validation:

1. **Syntax Validation** - OPA format checking
2. **Structural Validation** - Required components check
3. **Logic Validation** - Consistency and completeness
4. **Security Validation** - Best practices review

## Test Scenarios

Automatically generates test scenarios:

- **Skip Tests** - Non-target resource types
- **Pass Tests** - Compliant configurations
- **Fail Tests** - Non-compliant configurations
- **Edge Cases** - Boundary conditions

## Security Analysis

Provides security scoring (0-100) based on:

- Fail-safe defaults
- Input validation coverage
- Resource type checking
- IPv6 support
- Best practice adherence

## Supported Platforms

### Cloud Providers
- ✅ AWS (EC2, IAM, S3, RDS, etc.)
- ✅ Azure (Compute, Storage, KeyVault, etc.)
- ✅ GCP (Compute, Storage, Container, etc.)
- ✅ OCI (Core, Container, etc.)

### Frameworks
- CIS Benchmarks
- NIST Controls
- PCI-DSS
- SOC2
- Custom frameworks

## Advanced Features

### Custom Templates
Add your own templates in `templates/` directory:

```yaml
# templates/my_template.yaml
my_custom_pattern:
  resource_type: "Custom::Resource::Type"
  framework: "My Framework"
  patterns:
    # Define custom patterns
```

### Batch Processing
Process multiple policies:

```bash
# Process directory of configs
docker run -v $(pwd):/workspace rego-policy-generator batch /workspace/configs/
```

### Integration Examples

#### CI/CD Pipeline
```yaml
# .github/workflows/policy-validation.yml
- name: Validate Policies
  run: |
    docker run -v $(pwd):/workspace rego-policy-generator validate /workspace/policies/*.rego
```

#### Terraform Integration
```hcl
# Generate policies for Terraform resources
resource "local_file" "security_policy" {
  content = data.external.policy_generator.result.policy_content
  filename = "policies/terraform_policy.rego"
}
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## License

MIT License - See LICENSE file for details

## Support

- 📖 Documentation: See `/docs` directory
- 🐛 Issues: Create GitHub issue
- 💬 Discussions: GitHub discussions
- 📧 Email: support@example.com

---

**Built with ❤️ for the security community**