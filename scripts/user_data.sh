#!/bin/bash

set -e

REGION="${AWS_REGION:-ap-northeast-1}"

echo "Starting WireGuard setup..."

dnf update -y

dnf install -y wireguard-tools

dnf install -y amazon-cloudwatch-agent

echo "Fetching WireGuard configuration from Parameter Store..."

PRIVATE_KEY=$(aws ssm get-parameter --name private-key --with-decryption --region "$REGION" --query 'Parameter.Value' --output text)
PEER_PUBLIC_KEY=$(aws ssm get-parameter --name peer-public-key --region "$REGION" --query 'Parameter.Value' --output text)
SERVER_ADDRESS=$(aws ssm get-parameter --name server-address --region "$REGION" --query 'Parameter.Value' --output text)
PEER_ADDRESS=$(aws ssm get-parameter --name peer-address --region "$REGION" --query 'Parameter.Value' --output text)
PEER_ALLOWED_IPS=$(aws ssm get-parameter --name peer-allowed-ips --region "$REGION" --query 'Parameter.Value' --output text)

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $SERVER_ADDRESS
ListenPort = 51820

[Peer]
PublicKey = $PEER_PUBLIC_KEY
AllowedIPs = $PEER_ALLOWED_IPS
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf

echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

INSTANCE_ID=$(ec2-metadata --instance-id | cut -d ' ' -f 2)
EIP_ALLOC_ID="${EIP_ALLOCATION_ID}"

if [ -n "$EIP_ALLOC_ID" ]; then
    echo "Associating Elastic IP..."
    aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$EIP_ALLOC_ID" --region "$REGION"
fi

cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/ec2/wireguard",
            "log_stream_name": "{instance_id}/messages"
          }
        ]
      }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

echo "WireGuard setup completed successfully"
wg show
