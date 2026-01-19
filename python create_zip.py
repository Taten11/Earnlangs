import os
import zipfile

# Define the folder structure and files with their content
files = {
    "index.html": """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Landing Page</title>
<link rel="stylesheet" href="style.css">
<script src="script.js"></script>
</head>
<body>
<h1>Welcome to Dream Earning</h1>
</body>
</html>
""",
    "style.css":
    "/* Global Styles */\nbody { font-family: Arial, sans-serif; }",
    "script.js": "// Frontend JS\nconsole.log('Dream Earning JS loaded');",
    "main.py": "# Main application entry point\nprint('App started')",
    "pyproject.toml": "[tool.poetry]\nname = 'dream_earning'",
    "uv.lock": "",
    ".replit": "run = 'python main.py'",
    "replit.md": "# Dream Earning Project",
    "templates/dashboard.html": "<!-- User Dashboard -->",
    "templates/tasks.html": "<!-- Tasks page -->",
    "templates/submit.html": "<!-- Submit task -->",
    "templates/history.html": "<!-- Submission history -->",
    "templates/signup.html": "<!-- Signup page -->",
    "templates/login.html": "<!-- Login page -->",
    "templates/admin.html": "<!-- Admin main -->",
    "templates/admin/dashboard.html": "<!-- Admin dashboard -->",
    "templates/admin/users.html": "<!-- User management -->",
    "templates/admin/edit_user.html": "<!-- Edit user -->",
    "templates/admin/tasks.html": "<!-- Admin task management -->",
    "templates/admin/add_task.html": "<!-- Add task -->",
    "templates/admin/edit_task.html": "<!-- Edit task -->",
    "templates/admin/payouts.html": "<!-- Payout management -->",
    "templates/admin/submissions.html": "<!-- User submission review -->",
}

# Create directories
for file_path in files:
    dir_name = os.path.dirname(file_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)

# Write files
for file_path, content in files.items():
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

# Create ZIP
zip_name = "dream_earning.zip"
with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zipf:
    for file_path in files:
        zipf.write(file_path)

print(f"ZIP file '{zip_name}' created successfully!")
