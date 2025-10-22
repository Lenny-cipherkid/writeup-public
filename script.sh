#!/bin/bash

# DevOps-Playground HTB Machine Installation Script
# OS: Ubuntu Server 22.04 LTS
# Machine Type: Easy
# Author: HTB Machine Creator

set -e

echo "=========================================================="
echo "DevOps-Playground HTB Machine Installation Script"
echo "=========================================================="
echo "This script will configure Ubuntu Server 22.04 LTS"
echo "for the DevOps-Playground HTB machine."
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Starting DevOps-Playground machine setup..."

# 1. System Updates
print_status "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y

# Set hostname
print_status "Setting hostname to devops-playground..."
hostnamectl set-hostname devops-playground
echo "127.0.1.1 devops-playground.htb devops-playground" >> /etc/hosts

# Set timezone and locale
print_status "Configuring timezone and locale..."
timedatectl set-timezone UTC
locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8

# 2. Install required packages
print_status "Installing required packages..."
apt install -y nginx python3 python3-pip python3-venv git docker.io openssh-server sudo curl wget unzip cron

# 3. Configure networking
print_status "Configuring network interfaces..."
apt purge -y netplan.io nplan 2>/dev/null || true
rm -rf /etc/netplan/* 2>/dev/null || true

cat > /etc/network/interfaces << 'EOF'
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback

auto ens33
iface ens33 inet dhcp
EOF

# 4. Create users
print_status "Creating users..."

# Create developer user
useradd -m -s /bin/bash developer
echo "developer:CodePushDeploy2024!" | chpasswd

# Add developer to docker group
usermod -aG docker developer

# Set root password
echo "root:SecureRootAccess2024!" | chpasswd

# 5. Configure SSH
print_status "Configuring SSH..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh

# 6. Create directory structure
print_status "Creating directory structure..."
mkdir -p /var/www/html
mkdir -p /opt/deployapi
mkdir -p /opt/deployments
mkdir -p /var/log/deployapi
mkdir -p /tmp/deployments

chown -R developer:developer /opt/deployapi
chown -R developer:developer /opt/deployments
chown -R developer:developer /var/log/deployapi
chown -R developer:developer /tmp/deployments

# 7. Create Flask API
print_status "Creating Flask API..."

# Create Python virtual environment
python3 -m venv /opt/deployapi/venv
source /opt/deployapi/venv/bin/activate

# Install Flask
pip3 install flask gunicorn

# Create Flask application
cat > /opt/deployapi/app.py << 'EOF'
from flask import Flask, request, jsonify
from functools import wraps
import subprocess
import os

app = Flask(__name__)

# Hardcoded credentials (VULNERABLE)
VALID_USERNAME = "deploy_user"
VALID_PASSWORD = "D3pl0y_P@ssw0rd_2024!"

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != VALID_USERNAME or auth.password != VALID_PASSWORD:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return jsonify({
        "message": "DevOps Deployment API v1.0",
        "endpoints": [
            "/api/status",
            "/api/deploy"
        ],
        "note": "Authentication required for deployment endpoints"
    })

@app.route('/api/status')
def status():
    return jsonify({
        "status": "online",
        "deployments": 0,
        "last_deployment": "never"
    })

@app.route('/api/deploy', methods=['POST'])
@require_auth
def deploy():
    data = request.get_json()
    
    if not data or 'file' not in data:
        return jsonify({"error": "Missing 'file' parameter"}), 400
    
    filename = data['file']
    
    # VULNERABLE: Command injection!
    # No input validation or sanitization
    try:
        command = f"echo 'Deploying {filename}...' && ls -la /tmp/"
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        
        return jsonify({
            "status": "success",
            "message": f"Deployment initiated for {filename}",
            "output": result
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "output": e.output
        }), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
EOF

chown developer:developer /opt/deployapi/app.py

deactivate

# 8. Create systemd service for Flask API
print_status "Creating systemd service for API..."

cat > /etc/systemd/system/deployapi.service << 'EOF'
[Unit]
Description=DevOps Deployment API
After=network.target

[Service]
Type=simple
User=developer
WorkingDirectory=/opt/deployapi
Environment="PATH=/opt/deployapi/venv/bin"
ExecStart=/opt/deployapi/venv/bin/python3 /opt/deployapi/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable deployapi.service
systemctl start deployapi.service

# 9. Configure Nginx
print_status "Configuring Nginx..."

# Create main website
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevOps Playground - Deployment Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        header {
            background: rgba(0, 0, 0, 0.3);
            padding: 2rem;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        main {
            flex: 1;
            max-width: 900px;
            margin: 2rem auto;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        }
        .section {
            margin: 2rem 0;
            padding: 1.5rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            border-left: 4px solid #4caf50;
        }
        h2 {
            color: #4caf50;
            margin-bottom: 1rem;
        }
        code {
            background: rgba(0, 0, 0, 0.3);
            padding: 0.3rem 0.6rem;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
        .endpoint {
            margin: 0.5rem 0;
            padding: 0.8rem;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 5px;
        }
        footer {
            text-align: center;
            padding: 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            margin-top: auto;
        }
    </style>
</head>
<body>
    <header>
        <h1>🚀 DevOps Playground</h1>
        <p>Automated Deployment Dashboard</p>
    </header>
    
    <main>
        <div class="section">
            <h2>📡 API Documentation</h2>
            <p>Our deployment API allows you to manage application deployments programmatically.</p>
            <div class="endpoint">
                <strong>GET</strong> <code>/api/</code> - API Information
            </div>
            <div class="endpoint">
                <strong>GET</strong> <code>/api/status</code> - Check deployment status
            </div>
            <div class="endpoint">
                <strong>POST</strong> <code>/api/deploy</code> - Initiate deployment (Auth required)
            </div>
        </div>
        
        <div class="section">
            <h2>📚 Resources</h2>
            <p>Check out our deployment scripts and configurations in the <code>/deployments</code> directory.</p>
            <p>API documentation is available at <code>/docs</code></p>
        </div>
        
        <div class="section">
            <h2>⚙️ System Status</h2>
            <p>All systems operational</p>
            <p>Last deployment: Never</p>
        </div>
    </main>
    
    <footer>
        <p>&copy; 2024 DevOps Playground. Built with ❤️ by the Dev Team.</p>
    </footer>
</body>
</html>
EOF

# Create docs directory
mkdir -p /var/www/html/docs
cat > /var/www/html/docs/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>API Documentation</title>
    <style>
        body { font-family: monospace; padding: 2rem; background: #1e1e1e; color: #fff; }
        h1 { color: #4caf50; }
        code { background: #333; padding: 0.2rem 0.5rem; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Deployment API Documentation</h1>
    <p>For internal use only. Authentication required.</p>
    <p>Contact the development team for credentials.</p>
</body>
</html>
EOF

# Configure Nginx
cat > /etc/nginx/sites-available/default << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.html;
    
    server_name _;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location /deployments {
        alias /opt/deployments;
        autoindex off;
    }
}
EOF

# Test and restart Nginx
nginx -t
systemctl restart nginx
systemctl enable nginx

# 10. Create Git repository with vulnerable history
print_status "Creating Git repository with credentials..."

cd /opt/deployments

# Initialize git repo
sudo -u developer git init
sudo -u developer git config user.email "dev@devops-playground.htb"
sudo -u developer git config user.name "developer"

# Create initial files
cat > README.md << 'EOF'
# Deployment Scripts

This repository contains our deployment automation scripts.

## Usage

Use the API to trigger deployments. See `/docs` for more information.
EOF

cat > deploy.sh << 'EOF'
#!/bin/bash
# Simple deployment script
echo "Deploying application..."
EOF

chmod +x deploy.sh

# First commit
sudo -u developer git add README.md deploy.sh
sudo -u developer git commit -m "Initial commit"

# Create config with credentials (this will be "removed" later)
cat > config.yaml << 'EOF'
api:
  endpoint: "http://localhost:5000"
  username: "deploy_user"
  password: "D3pl0y_P@ssw0rd_2024!"
deployment:
  path: "/tmp/deployments"
  timeout: 300
EOF

sudo -u developer git add config.yaml
sudo -u developer git commit -m "Add deployment configuration"

# "Remove" credentials (but they stay in history)
cat > config.yaml << 'EOF'
api:
  endpoint: "http://localhost:5000"
  username: "REDACTED"
  password: "REDACTED"
deployment:
  path: "/tmp/deployments"
  timeout: 300
EOF

sudo -u developer git add config.yaml
sudo -u developer git commit -m "Remove sensitive credentials from config"

# Make .git accessible via web (VULNERABLE)
chmod -R 755 /opt/deployments/.git

cd /root

# 11. Setup Docker
print_status "Configuring Docker..."

systemctl enable docker
systemctl start docker

# Pull Ubuntu image
docker pull ubuntu:latest

# 12. Set up cron jobs
print_status "Setting up cron jobs..."

cat > /etc/cron.d/devops-logrotate << 'EOF'
# Rotate API logs daily
0 0 * * * developer /usr/bin/find /var/log/deployapi -name "*.log" -mtime +7 -delete 2>/dev/null
EOF

cat > /etc/cron.d/devops-cleanup << 'EOF'
# Clean old deployment files every hour
0 * * * * developer /usr/bin/find /tmp/deployments -type f -mmin +60 -delete 2>/dev/null
EOF

chmod 644 /etc/cron.d/devops-logrotate
chmod 644 /etc/cron.d/devops-cleanup

# 13. Create and place flags
print_status "Creating flags..."

# Generate MD5 flags
USER_FLAG=$(echo -n "DevOps_User_$(date +%s)" | md5sum | cut -d' ' -f1)
ROOT_FLAG=$(echo -n "DevOps_Root_$(date +%s)" | md5sum | cut -d' ' -f1)

# Place user flag
echo "$USER_FLAG" > /home/developer/user.txt
chown root:developer /home/developer/user.txt
chmod 644 /home/developer/user.txt

# Place root flag
echo "$ROOT_FLAG" > /root/root.txt
chown root:root /root/root.txt
chmod 640 /root/root.txt

# 14. Secure history files
print_status "Securing history files..."

# Redirect history to /dev/null for all users
echo 'export HISTFILE=/dev/null' >> /etc/profile
echo 'export HISTFILE=/dev/null' >> /home/developer/.bashrc
echo 'export HISTFILE=/dev/null' >> /root/.bashrc

# Remove existing history
rm -f /home/developer/.bash_history
rm -f /root/.bash_history
rm -f /home/developer/.python_history
rm -f /root/.python_history
rm -f /home/developer/.viminfo
rm -f /root/.viminfo

# Create immutable empty history files
touch /home/developer/.bash_history /root/.bash_history
chown developer:developer /home/developer/.bash_history
chattr +i /home/developer/.bash_history /root/.bash_history 2>/dev/null || true

# 15. Final permissions and ownership
print_status "Setting final permissions..."

# Web files
chown -R www-data:www-data /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;
find /var/www/html -type d -exec chmod 755 {} \;

# API files
chown -R developer:developer /opt/deployapi
chmod 755 /opt/deployapi
chmod 644 /opt/deployapi/app.py

# Git repository
chown -R developer:developer /opt/deployments
chmod -R 755 /opt/deployments

# Log directories
chown -R developer:developer /var/log/deployapi
chmod 755 /var/log/deployapi

# 16. Security hardening
print_status "Applying security hardening..."

# Disable unnecessary services
systemctl disable bluetooth 2>/dev/null || true
systemctl disable cups 2>/dev/null || true
systemctl disable avahi-daemon 2>/dev/null || true

# Ensure services are running
systemctl restart nginx
systemctl restart deployapi.service
systemctl restart docker
systemctl restart cron
systemctl restart ssh

# 17. Verify services
print_status "Verifying services..."

sleep 3

# Check Nginx
if systemctl is-active --quiet nginx; then
    print_success "Nginx is running"
else
    print_error "Nginx failed to start"
fi

# Check API
if systemctl is-active --quiet deployapi.service; then
    print_success "DeployAPI is running"
else
    print_error "DeployAPI failed to start"
fi

# Check Docker
if systemctl is-active --quiet docker; then
    print_success "Docker is running"
else
    print_error "Docker failed to start"
fi

# Check SSH
if systemctl is-active --quiet ssh; then
    print_success "SSH is running"
else
    print_error "SSH failed to start"
fi

# Test API endpoint
if curl -s http://localhost:5000/ | grep -q "DevOps Deployment API"; then
    print_success "API endpoint responding correctly"
else
    print_warning "API endpoint may not be responding correctly"
fi

# Test Nginx
if curl -s http://localhost/ | grep -q "DevOps Playground"; then
    print_success "Nginx serving website correctly"
else
    print_warning "Nginx may not be serving correctly"
fi

# 18. Create machine info file
print_status "Creating machine information file..."

cat > /root/machine_info.txt << EOF
==========================================================
DevOps-Playground HTB Machine Information
==========================================================

Machine Type: Easy
OS: Ubuntu Server 22.04 LTS
Hostname: devops-playground.htb

CREDENTIALS:
- User: developer | Password: CodePushDeploy2024!
- Root: root | Password: SecureRootAccess2024!

API CREDENTIALS (found in Git history):
- Username: deploy_user
- Password: D3pl0y_P@ssw0rd_2024!

FLAGS:
- User Flag: $USER_FLAG (located in /home/developer/user.txt)
- Root Flag: $ROOT_FLAG (located in /root/root.txt)

SERVICES:
- HTTP (Port 80): Nginx reverse proxy + static site
- API (Port 5000): Flask deployment API (internal only)
- SSH (Port 22): Standard OpenSSH
- Docker: unix socket (/var/run/docker.sock)

EXPLOITATION PATH:
1. Web Enumeration → Find /deployments/.git exposed
2. Git Dumping → Extract credentials from commit history
3. API Testing → Discover command injection in /api/deploy
4. Foothold → Execute reverse shell via command injection
5. Privilege Escalation → Abuse docker group membership

INTENDED VULNERABILITIES:
- Exposed .git directory with credentials in history
- Command injection in Flask API /api/deploy endpoint
- Developer user in docker group (privilege escalation)

TESTING CHECKLIST:
□ Port scan shows 22 and 80 open
□ Website loads at http://IP/
□ API responds at http://IP/api/
□ Git repository accessible at http://IP/deployments/.git/
□ Git history contains credentials
□ API accepts credentials and executes commands
□ Command injection works for reverse shell
□ Docker command works as developer user
□ Docker privilege escalation to root works

USEFUL COMMANDS FOR TESTING:
# Test API without auth
curl http://localhost/api/

# Test API with auth
curl -u deploy_user:D3pl0y_P@ssw0rd_2024! http://localhost/api/deploy -X POST -H "Content-Type: application/json" -d '{"file":"test"}'

# Test command injection
curl -u deploy_user:D3pl0y_P@ssw0rd_2024! http://localhost/api/deploy -X POST -H "Content-Type: application/json" -d '{"file":"test; id"}'

# Dump git repo
git-dumper http://localhost/deployments/.git/ /tmp/repo

# Check git history
cd /tmp/repo && git log --oneline && git show [commit]

# Test docker access as developer
su - developer
docker ps
docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh

Created: $(date)
==========================================================
EOF

chmod 600 /root/machine_info.txt

# 19. Create test script for validation
print_status "Creating validation test script..."

cat > /root/test_machine.sh << 'EOF'
#!/bin/bash

echo "=========================================="
echo "DevOps-Playground Machine Validation Test"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

test_count=0
pass_count=0

run_test() {
    test_count=$((test_count + 1))
    echo -n "Test $test_count: $1... "
    if eval "$2" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        pass_count=$((pass_count + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi
}

# Run tests
run_test "Nginx is running" "systemctl is-active --quiet nginx"
run_test "DeployAPI is running" "systemctl is-active --quiet deployapi.service"
run_test "Docker is running" "systemctl is-active --quiet docker"
run_test "SSH is running" "systemctl is-active --quiet ssh"
run_test "Website accessible" "curl -s http://localhost/ | grep -q 'DevOps Playground'"
run_test "API accessible" "curl -s http://localhost/api/ | grep -q 'DevOps Deployment API'"
run_test "Git repo exists" "test -d /opt/deployments/.git"
run_test "Git has commits" "cd /opt/deployments && git log | grep -q 'credentials'"
run_test "User flag exists" "test -f /home/developer/user.txt"
run_test "Root flag exists" "test -f /root/root.txt"
run_test "Developer in docker group" "groups developer | grep -q docker"
run_test "Ubuntu docker image exists" "docker images | grep -q ubuntu"

echo ""
echo "=========================================="
echo "Results: $pass_count/$test_count tests passed"
echo "=========================================="

if [ $pass_count -eq $test_count ]; then
    echo -e "${GREEN}All tests passed! Machine is ready.${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check the configuration.${NC}"
    exit 1
fi
EOF

chmod +x /root/test_machine.sh

# 20. Run validation tests
print_status "Running validation tests..."
echo ""

/root/test_machine.sh

echo ""
print_success "=========================================="
print_success "DevOps-Playground setup completed!"
print_success "=========================================="
echo ""
print_warning "Important Information:"
echo ""
echo -e "  ${YELLOW}User Flag:${NC} $USER_FLAG"
echo -e "  ${YELLOW}Root Flag:${NC} $ROOT_FLAG"
echo ""
echo -e "  ${YELLOW}SSH Access:${NC} ssh developer@[IP]"
echo -e "  ${YELLOW}Password:${NC} CodePushDeploy2024!"
echo ""
echo -e "  ${YELLOW}API Credentials (in Git history):${NC}"
echo -e "  Username: deploy_user"
echo -e "  Password: D3pl0y_P@ssw0rd_2024!"
echo ""
print_warning "Next Steps:"
echo "1. Shutdown the VM: sudo shutdown -h now"
echo "2. Take a VM snapshot (clean state)"
echo "3. Configure VM: 2GB RAM, 2 CPU cores"
echo "4. Test the full exploitation path"
echo "5. Take screenshots for writeup"
echo "6. Package everything for HTB submission"
echo ""
print_warning "Testing Commands:"
echo "  Test website: curl http://localhost/"
echo "  Test API: curl http://localhost/api/"
echo "  Run tests: /root/test_machine.sh"
echo ""
print_success "Machine is ready for HTB submission!"
print_success "Check /root/machine_info.txt for detailed information"
echo ""
