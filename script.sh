rm -rf .git
sudo -u developer git init
sudo -u developer git config user.email "dev@devops-playground.htb"
sudo -u developer git config user.name "developer"

# Crée les fichiers initiaux
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

# Premier commit
sudo -u developer git add README.md deploy.sh
sudo -u developer git commit -m "Initial commit"

# Crée config.yaml AVEC les credentials
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

# Maintenant "supprime" les credentials (mais ils restent dans l'historique)
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

# Assure-toi que .git est accessible
chmod -R 755 /opt/deployments/.git

# Vérifie que ça a fonctionné
git log --oneline
```
