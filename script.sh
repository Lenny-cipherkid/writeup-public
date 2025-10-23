#!/bin/bash

# Script de correction du dépôt Git
# Exécute en tant que root

echo "Correction du dépôt Git..."

# Va dans le dépôt
cd /opt/deployments

# Supprime et recrée le dépôt
rm -rf .git
sudo -u developer git init
sudo -u developer git config user.email "dev@devops-playground.htb"
sudo -u developer git config user.name "developer"

# Crée README.md
cat > README.md <<'ENDOFFILE'
# Deployment Scripts

This repository contains our deployment automation scripts.

## Usage

Use the API to trigger deployments. See `/docs` for more information.
ENDOFFILE

# Crée deploy.sh
cat > deploy.sh <<'ENDOFFILE'
#!/bin/bash
# Simple deployment script
echo "Deploying application..."
ENDOFFILE

chmod +x deploy.sh
chown developer:developer README.md deploy.sh

# Premier commit
sudo -u developer git add README.md deploy.sh
sudo -u developer git commit -m "Initial commit"

# Crée config.yaml AVEC credentials
cat > config.yaml <<'ENDOFFILE'
api:
  endpoint: "http://localhost:5000"
  username: "deploy_user"
  password: "D3pl0y_P@ssw0rd_2024!"
deployment:
  path: "/tmp/deployments"
  timeout: 300
ENDOFFILE

chown developer:developer config.yaml
sudo -u developer git add config.yaml
sudo -u developer git commit -m "Add deployment configuration"

# Supprime les credentials du fichier (mais ils restent dans l'historique)
cat > config.yaml <<'ENDOFFILE'
api:
  endpoint: "http://localhost:5000"
  username: "REDACTED"
  password: "REDACTED"
deployment:
  path: "/tmp/deployments"
  timeout: 300
ENDOFFILE

chown developer:developer config.yaml
sudo -u developer git add config.yaml
sudo -u developer git commit -m "Remove sensitive credentials from config"

# Rend .git accessible via web
chmod -R 755 /opt/deployments/.git

echo "Vérification de l'historique Git..."
sudo -u developer git log --oneline

echo ""
echo "Test de présence des credentials dans l'historique..."
if sudo -u developer git log -p | grep -q "D3pl0y_P@ssw0rd_2024!"; then
    echo "✓ Les credentials sont bien dans l'historique Git"
else
    echo "✗ ERREUR: Les credentials ne sont pas dans l'historique"
fi

echo ""
echo "Relance le test de validation: /root/test_machine.sh"
