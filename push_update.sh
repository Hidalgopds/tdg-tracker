#!/bin/bash
cd "$(dirname "$0")"
git add app.py templates/index.html
git commit -m "Add TDG No, MBR No, MBR Skid fields; Prev % column; new DB columns"
git push
echo ""
echo "Done! Render will redeploy in ~2 min."
read -p "Press Enter to close..."
