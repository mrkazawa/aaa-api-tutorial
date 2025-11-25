# Quick Start Guide for Beginners

**New to Docker, APIs, or command line?** This guide will help you get started.

---

## Step 0: Install Required Software

### 1. Install Docker Desktop

**What is Docker?** It's a tool that runs applications in isolated containers, so you don't need to install MySQL, Node.js, etc. on your computer directly.

- **Windows/Mac:** Download from [docker.com](https://www.docker.com/products/docker-desktop)
- **Linux:** Follow [installation guide](https://docs.docker.com/engine/install/)

**Test it works:**
```bash
docker --version
docker-compose --version
```

### 2. Install a Text Editor

We recommend **VS Code** (free): [code.visualstudio.com](https://code.visualstudio.com/)

Other options: Sublime Text, Atom, or any code editor

### 3. Open Terminal/Command Line

- **Windows:** Search for "Command Prompt" or "PowerShell"
- **Mac:** Search for "Terminal" 
- **Linux:** You probably know this already 😉

---

## Step 1: Create Your Project Folder

```bash
# Navigate to where you want your project (e.g., Desktop)
cd Desktop

# Create and enter the project folder
mkdir api-app-tutorial
cd api-app-tutorial
```

**What this does:** Creates a new folder called `api-app-tutorial` and moves into it.

---

## Step 2: Follow Part 1 of Tutorial

Now open the tutorial and follow Part 1:

👉 **[Start with Part 1: Docker Compose Setup](./plan/1_docker_compose_setup.md)**

---

## Common Beginner Questions

### Q: What's the difference between a file and a folder?
- **Folder/Directory:** Contains other files/folders (e.g., `api/`, `src/`)
- **File:** Contains code or data (e.g., `server.js`, `.env`)

### Q: What does `mkdir` mean?
**Make Directory** - Creates a new folder.

```bash
mkdir my-folder        # Creates one folder
mkdir -p api/src      # Creates api folder AND src folder inside it
```

### Q: What does `cd` mean?
**Change Directory** - Move into a folder.

```bash
cd api              # Move into api folder
cd ..               # Move up one level (out of current folder)
cd ~                # Go to home directory
pwd                 # Print Working Directory (shows where you are)
```

### Q: How do I know if a command worked?
- **No error message = Success!** 
- If you see an error (usually in red), read it carefully
- Check [COMMON_ISSUES.md](./COMMON_ISSUES.md) for solutions

### Q: What if I close the terminal?
You'll need to navigate back to your project folder:

```bash
cd Desktop/api-app-tutorial   # Or wherever you created it
```

### Q: Can I use copy-paste for code?
**For learning: Type it yourself!** You'll learn much better.

**For speed:** Copy-paste is fine, but understand what each line does.

### Q: What are those `$` and `#` symbols?
- `$` at start of line = "This is a command to type in terminal"
- `#` at start of line = "This is a comment, don't type it"

**Example:**
```bash
# This is a comment explaining what we're doing
$ docker-compose up    # Type this (without the $)
```

### Q: Do I need to be online?
**Yes**, for:
- Downloading Docker images (first time only)
- Installing npm packages (first time only)
- Google OAuth (Part 3)

After initial setup, most work can be done offline.

---

## Troubleshooting Your First Run

### Problem: "docker: command not found"
**Solution:** Docker isn't installed or not in PATH. Restart computer after installing Docker.

### Problem: "Permission denied"
**Solution (Mac/Linux):** Try with `sudo`:
```bash
sudo docker-compose up
```

**Solution (Windows):** Run Command Prompt as Administrator.

### Problem: Port 3000 already in use
**Solution:** Something else is using that port. Either:
1. Stop that program
2. Or change port in `.env`:
   ```
   PORT=3001
   ```

### Problem: Can't find the file I just created
**Solution:** Make sure you're in the right folder:
```bash
pwd                    # Shows current directory
ls                     # Lists files in current directory (Mac/Linux)
dir                    # Lists files in current directory (Windows)
```

---

## Understanding the Commands You'll Use

### Docker Commands

```bash
# Start all services (API, database, etc.)
docker-compose up -d

# View logs (what's happening)
docker-compose logs -f api

# Stop all services
docker-compose down

# Restart a service
docker-compose restart api

# Check which containers are running
docker-compose ps
```

### API Testing Commands

```bash
# Test if API is running (Windows: use PowerShell or install curl)
curl http://localhost:3000/health

# Register a user (example from tutorial)
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"Test123!"}'
```

**Can't use curl?** Install [Postman](https://www.postman.com/downloads/) (free, visual tool for testing APIs)

---

## Reading File Paths

When you see: `api/src/controllers/authController.js`

This means:
```
api-app-tutorial/          ← Your project root
  └── api/                 ← Folder
      └── src/             ← Folder inside api
          └── controllers/ ← Folder inside src
              └── authController.js ← File you need to create
```

---

## Tips for Success

1. ✅ **Read error messages carefully** - They usually tell you what's wrong
2. ✅ **One step at a time** - Don't rush ahead
3. ✅ **Test after each step** - Make sure it works before continuing
4. ✅ **Use the checklist** - [IMPLEMENTATION_CHECKLIST.md](./IMPLEMENTATION_CHECKLIST.md)
5. ✅ **Google is your friend** - Search for error messages
6. ✅ **Ask for help** - Instructor, classmates, or online forums

---

## Visual Overview: What You're Building

```
┌─────────────────────────────────────┐
│  Your Computer                       │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  Docker                         │ │
│  │                                 │ │
│  │  ┌──────┐  ┌──────┐  ┌──────┐ │ │
│  │  │ API  │  │MySQL │  │Grafana│ │ │
│  │  │:3000 │  │:3306 │  │:3001 │ │ │
│  │  └──────┘  └──────┘  └──────┘ │ │
│  │                                 │ │
│  └────────────────────────────────┘ │
│                                      │
│  Access via browser:                 │
│  → http://localhost:3000 (API)      │
│  → http://localhost:3001 (Grafana)  │
└─────────────────────────────────────┘
```

---

## Next Steps

1. ✅ Make sure Docker is installed and running
2. ✅ Open your terminal
3. ✅ Create project folder
4. ✅ Open VS Code in that folder
5. ✅ Start with **[Part 1: Docker Compose Setup](./plan/1_docker_compose_setup.md)**

---

## Need More Help?

- 📖 **Stuck on a specific error?** Check [COMMON_ISSUES.md](./COMMON_ISSUES.md)
- 📋 **Want to track progress?** Use [IMPLEMENTATION_CHECKLIST.md](./IMPLEMENTATION_CHECKLIST.md)
- 💬 **Still confused?** Ask your instructor or search the error message online

**Remember:** Everyone starts as a beginner. Take your time and enjoy learning! 🚀
