#!/bin/bash
# TDG Tracker - Create GitHub repo and push files
# Run this from Git Bash in the tdg-tracker folder

TOKEN="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"
REPO="tdg-tracker"

echo "=== Creating GitHub repo ==="

# Create repo
curl -s -X POST https://api.github.com/user/repos \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$REPO\",\"private\":true,\"description\":\"TDG Daily Log - MBR Texas Field Operations\"}" \
  | grep -E '"full_name"|"html_url"|"message"'

echo ""
echo "=== Getting username ==="
USERNAME=$(curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/user | grep '"login"' | head -1 | cut -d'"' -f4)
echo "Username: $USERNAME"

echo ""
echo "=== Pushing files ==="
git init
git config user.email "dshidalgop@gmail.com"
git config user.name "Hidalgopds"
git add .
git commit -m "Initial commit - TDG Daily Log app"
git branch -M main
git remote add origin https://$TOKEN@github.com/$USERNAME/$REPO.git
git push -u origin main

echo ""
echo "=== Done! ==="
echo "Repo: https://github.com/$USERNAME/$REPO"
echo ""
read -p "Press Enter to close..."
