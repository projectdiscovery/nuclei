cd /workspaces/nuclei/nuclei-templates/ 2>/dev/null

if [ -d ".git" ]; then
    echo "[*] Updating official Nuclei templates..."
    git pull --quiet
    echo "[✓] Updated successfully."
else
    echo "[!] Directory not a git repo. Cloning fresh copy..."
    git clone https://github.com/projectdiscovery/nuclei-templates.git /workspaces/nuclei/nuclei-templates/
    echo "[✓] Cloned fresh copy."
fi
