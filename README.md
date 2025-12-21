# WireGuard VPN Infrastructure

AWS CDK project for establishing a WireGuard VPN connection between AWS and a local LLM server.

## Architecture

This infrastructure provides:
- VPC with public and private subnets across 2 Availability Zones
- WireGuard VPN server on EC2 with AutoScaling Group (desired capacity: 1)
- Elastic IP for stable endpoint
- Lambda functions for automated EIP attachment and WireGuard configuration restoration
- CloudWatch monitoring and SNS alerts

## Prerequisites

- AWS CLI configured with appropriate credentials
- AWS CDK CLI installed (`npm install -g aws-cdk`)
- Python 3.9 or later
- WireGuard installed locally for key generation

## Project Structure

```
infra/
├── app.py                      # CDK app entry point
├── requirements.txt            # Python dependencies
├── cdk.json                    # CDK configuration
├── stacks/                     # CDK stack definitions
├── lambda_functions/           # Lambda function code
├── scripts/                    # Utility scripts
└── config/                     # Configuration templates
```

## Setup

### 1. Create Python Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate WireGuard Keys

```bash
# Create keys directory
mkdir -p keys

# Generate server keys
wg genkey | tee keys/server_private.key | wg pubkey > keys/server_public.key

# Generate peer (local LLM server) keys
wg genkey | tee keys/peer_private.key | wg pubkey > keys/peer_public.key
```

### 4. Store Keys in AWS Systems Manager Parameter Store

```bash
# Store server private key (encrypted)
aws ssm put-parameter \
  --name private-key \
  --type SecureString \
  --value "$(cat keys/server_private.key)"

# Store server public key
aws ssm put-parameter \
  --name public-key \
  --type String \
  --value "$(cat keys/server_public.key)"

# Store peer public key
aws ssm put-parameter \
  --name peer-public-key \
  --type String \
  --value "$(cat keys/peer_public.key)"

# Store VPN network configuration
aws ssm put-parameter \
  --name server-address \
  --type String \
  --value "10.200.0.1/24"

aws ssm put-parameter \
  --name peer-address \
  --type String \
  --value "10.200.0.2/32"

# Store peer allowed IPs (adjust as needed)
aws ssm put-parameter \
  --name peer-allowed-ips \
  --type String \
  --value "10.200.0.2/32"
```

### 5. Configure CDK Context (Optional)

Create `cdk.context.json` to specify your AWS account and region:

```json
{
  "account": "123456789012",
  "region": "ap-northeast-1"
}
```

Or set via environment variables:
```bash
export CDK_DEFAULT_ACCOUNT=123456789012
export CDK_DEFAULT_REGION=ap-northeast-1
```

### 6. Bootstrap CDK (First Time Only)

```bash
cdk bootstrap
```

### 7. Deploy Infrastructure

```bash
# Review changes
cdk diff

# Deploy all stacks
cdk deploy --all

# Or deploy specific stack
cdk deploy WireGuardNetworkStack
```

## Post-Deployment

### 1. Get Elastic IP Address

```bash
aws ec2 describe-addresses \
  --filters "Name=tag:Name,Values=WireGuardEIP" \
  --query 'Addresses[0].PublicIp' \
  --output text
```

### 2. Configure Local LLM Server

Create WireGuard configuration on your local LLM server:

```ini
[Interface]
PrivateKey = <peer_private_key from keys/peer_private.key>
Address = 10.200.0.2/32

[Peer]
PublicKey = <server_public_key from keys/server_public.key>
Endpoint = <Elastic_IP>:51820
AllowedIPs = 10.0.0.0/16, 10.200.0.0/24
PersistentKeepalive = 25
```

### 3. Start WireGuard on Local Server

```bash
# Linux
sudo wg-quick up wg0

# Check status
sudo wg show
```

### 4. Test Connection

```bash
# From local LLM server, ping the WireGuard server
ping 10.200.0.1

# Test connectivity to AWS VPC resources
ping 10.0.1.10  # Example private IP in VPC
```

## Monitoring

- CloudWatch Alarms are configured for:
  - Instance status checks
  - High CPU utilization
  - Network activity (potential connection issues)
- SNS notifications will be sent to the configured email address

## Troubleshooting

### Check WireGuard Status on EC2

```bash
# Connect via Systems Manager Session Manager
aws ssm start-session --target <instance-id>

# Check WireGuard status
sudo wg show

# Check WireGuard logs
sudo journalctl -u wg-quick@wg0
```

### Check Lambda Logs

```bash
# EIP Attach Lambda
aws logs tail /aws/lambda/WireGuardEIPAttach --follow

# WireGuard Restore Lambda
aws logs tail /aws/lambda/WireGuardRestore --follow
```

### Verify Security Group

```bash
aws ec2 describe-security-groups \
  --filters "Name=tag:Name,Values=WireGuardSecurityGroup" \
  --query 'SecurityGroups[0].IpPermissions'
```

## Cost Estimation

Approximate monthly costs (Tokyo region):
- EC2 t3.micro: ~$7.50
- EBS 8GB gp3: ~$0.80
- Elastic IP (attached): $0
- Lambda executions: ~$0.00
- CloudWatch Logs: ~$0.50
- CloudWatch Alarms: ~$0.30
- Data transfer: ~$1.00

**Total: ~$10/month**

## Cleanup

To avoid ongoing charges, destroy the infrastructure:

```bash
cdk destroy --all
```

Also delete Parameter Store parameters:

```bash
aws ssm delete-parameter --name private-key
aws ssm delete-parameter --name public-key
aws ssm delete-parameter --name peer-public-key
aws ssm delete-parameter --name server-address
aws ssm delete-parameter --name peer-address
aws ssm delete-parameter --name peer-allowed-ips
```

## Security Considerations

- WireGuard private keys are stored encrypted in Parameter Store
- Security group restricts WireGuard port access to your local IP only
- SSH access should use Systems Manager Session Manager (no SSH keys needed)
- Consider enabling VPC Flow Logs for network monitoring
- Regularly rotate WireGuard keys (recommended: annually)

## License

This project is licensed under the MIT License.
