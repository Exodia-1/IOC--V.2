# 🚀 Vercel Deployment - Step-by-Step Guide

## Prerequisites ✅

Before starting, make sure you have:
- [ ] A GitHub account
- [ ] Git installed on your computer
- [ ] Your API keys ready (optional - can add later)

---

## 📋 Step-by-Step Deployment

### Step 1: Push Code to GitHub (5 minutes)

#### Option A: If you already have a GitHub repository

1. **Open your terminal** in the project directory

2. **Add and commit all changes:**
```bash
git add .
git commit -m "Ready for Vercel deployment"
git push origin main
```

3. **Verify on GitHub:**
   - Go to your repository URL
   - Confirm you see these files in the root:
     - ✅ `package.json`
     - ✅ `vercel.json`
     - ✅ `api/` folder
     - ✅ `src/` folder

---

#### Option B: If you need to create a new GitHub repository

1. **Go to GitHub.com** and sign in

2. **Create new repository:**
   - Click the **"+"** icon (top right) → **"New repository"**
   - Repository name: `soc-ioc-analyzer` (or any name you like)
   - Choose **Public** or **Private**
   - **DO NOT** check "Add README" or ".gitignore"
   - Click **"Create repository"**

3. **Push your code:**
```bash
# In your project folder /app
cd /app

# Initialize git (if needed)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit - SOC IOC Analyzer"

# Add remote (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/soc-ioc-analyzer.git

# Push
git branch -M main
git push -u origin main
```

4. **Enter credentials when prompted:**
   - Username: Your GitHub username
   - Password: Use a **Personal Access Token** (not your password)
   
   **How to get a token:**
   - Go to: GitHub.com → Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Click "Generate new token (classic)"
   - Give it a name: "Vercel Deployment"
   - Select scopes: Check **"repo"** (full control of private repositories)
   - Click "Generate token"
   - **Copy the token** (you won't see it again!)
   - Use this token as your password when pushing

---

### Step 2: Sign Up / Sign In to Vercel (2 minutes)

1. **Go to Vercel:**
   - Open: https://vercel.com

2. **Sign in with GitHub:**
   - Click **"Sign Up"** (if new) or **"Login"** (if you have an account)
   - Click **"Continue with GitHub"**
   - Authorize Vercel to access your GitHub account
   - Click **"Authorize Vercel"**

3. **You'll be redirected to your Vercel Dashboard**

---

### Step 3: Import Your Project (3 minutes)

1. **From Vercel Dashboard:**
   - Click **"Add New..."** button (top right)
   - Select **"Project"** from dropdown

2. **Import Git Repository:**
   - You'll see a list of your GitHub repositories
   - Find **"soc-ioc-analyzer"** (or whatever you named it)
   - Click **"Import"** next to it

   **Can't see your repository?**
   - Click **"Adjust GitHub App Permissions"**
   - Select "All repositories" or choose specific ones
   - Click "Save"
   - Return to Vercel and refresh

---

### Step 4: Configure Project Settings (5 minutes)

After clicking Import, you'll see the "Configure Project" page:

#### 4.1 Project Name
- **Project Name:** `soc-ioc-analyzer` (or customize)
- This becomes part of your URL: `https://soc-ioc-analyzer.vercel.app`

#### 4.2 Framework Preset
- Vercel should auto-detect: **"Create React App"**
- If not, select it from dropdown

#### 4.3 Root Directory
- Leave as: **"./"** (default)
- This means the root of your repository

#### 4.4 Build Settings
Vercel auto-detects these (don't change unless needed):
- **Build Command:** `npm run build` ✅
- **Output Directory:** `build` ✅
- **Install Command:** `npm install` ✅

#### 4.5 Environment Variables (IMPORTANT! ⚠️)

**Scroll down to "Environment Variables" section**

You need to add your API keys here. Click to expand the section.

**Add these variables one by one:**

1. **AbuseIPDB API Key:**
   - Key: `ABUSEIPDB_API_KEY`
   - Value: Paste your key (get from https://www.abuseipdb.com/api)
   - Environment: **Production** (keep checked)
   - Click **"Add"**

2. **VirusTotal API Key:**
   - Key: `VIRUSTOTAL_API_KEY`
   - Value: Paste your key (get from https://www.virustotal.com/gui/join-us)
   - Environment: **Production**
   - Click **"Add"**

3. **URLScan API Key:**
   - Key: `URLSCAN_API_KEY`
   - Value: Paste your key (get from https://urlscan.io/about/api/)
   - Environment: **Production**
   - Click **"Add"**

4. **AlienVault API Key:**
   - Key: `ALIENVAULT_API_KEY`
   - Value: Paste your key (get from https://otx.alienvault.com/api)
   - Environment: **Production**
   - Click **"Add"**

5. **GreyNoise API Key:**
   - Key: `GREYNOISE_API_KEY`
   - Value: Paste your key (get from https://www.greynoise.io/)
   - Environment: **Production**
   - Click **"Add"**

**Don't have all API keys?**
- You can deploy without them
- The app will work, but those specific vendors won't return data
- You can add keys later in: Project Settings → Environment Variables

---

### Step 5: Deploy! (2-3 minutes)

1. **Review your settings:**
   - Framework: Create React App ✅
   - Build Command: npm run build ✅
   - Output Directory: build ✅
   - Environment Variables: Added ✅

2. **Click the big blue "Deploy" button**

3. **Wait for deployment:**
   - You'll see a build log with real-time progress
   - Steps you'll see:
     - 📦 Cloning repository
     - 📥 Installing dependencies
     - 🏗️ Building React app
     - 🐍 Setting up Python serverless function
     - ⚡ Deploying to edge network
   - **Total time:** ~2-3 minutes

4. **Watch for completion:**
   - ✅ Green checkmarks = success
   - ❌ Red X = error (see Step 7 for troubleshooting)

---

### Step 6: Success! Access Your App (1 minute)

When deployment finishes successfully:

1. **Celebration screen appears!** 🎉
   - Confetti animation
   - Your live URL displayed

2. **Your URL will be:**
   - Format: `https://[project-name]-[random].vercel.app`
   - Example: `https://soc-ioc-analyzer-abc123.vercel.app`

3. **Click "Visit" or click the URL**

4. **Test your app:**
   - Try analyzing: `8.8.8.8`
   - Check if results appear
   - Test different IOC types

---

### Step 7: If Deployment Fails (Troubleshooting)

#### Error: "Module not found"
**Solution:** 
- Check that `package.json` is at the repository root
- Verify the error logs for specific missing modules
- Common fix: Ensure all imports use correct paths

#### Error: "Build failed"
**Solution:**
- Click on the failed deployment
- Read the build logs carefully
- Look for the specific error message
- Common issues:
  - Missing dependencies
  - Import path errors
  - Syntax errors

#### Error: "Serverless Function Error"
**Solution:**
- Check `api/requirements.txt` exists
- Verify Python dependencies are correct
- Check backend logs in: Deployments → Functions tab

---

## 🔄 Adding API Keys Later

If you deployed without all API keys:

1. **Go to your Vercel Dashboard**
   - https://vercel.com/dashboard

2. **Click on your project**
   - Select "soc-ioc-analyzer"

3. **Go to Settings:**
   - Click "Settings" tab (top navigation)

4. **Add Environment Variables:**
   - Click "Environment Variables" (left sidebar)
   - Click "Add New" button
   - Enter Key name (e.g., `ABUSEIPDB_API_KEY`)
   - Enter Value (your API key)
   - Select "Production"
   - Click "Save"

5. **Redeploy:**
   - Go to "Deployments" tab
   - Find your latest deployment
   - Click the "..." menu → **"Redeploy"**
   - Wait for redeployment to complete

---

## 🌐 Custom Domain (Optional)

Want to use your own domain instead of `.vercel.app`?

1. **Buy a domain** (from GoDaddy, Namecheap, etc.)

2. **In Vercel:**
   - Project → Settings → Domains
   - Click "Add"
   - Enter your domain: `yourdomain.com`
   - Click "Add"

3. **Configure DNS:**
   - Vercel shows you DNS records to add
   - Go to your domain registrar
   - Add the DNS records Vercel provides
   - Wait for DNS propagation (up to 48 hours)

4. **Done!** Your app will be at `https://yourdomain.com`

---

## 🔄 Future Updates

After making code changes:

```bash
# Make your changes to code
# Then commit and push:

git add .
git commit -m "Description of changes"
git push origin main
```

**Vercel automatically redeploys!** 🚀
- No need to manually trigger
- Build starts automatically on push
- New version live in 2-3 minutes

---

## 📊 Monitoring Your App

### View Deployment Status
- Vercel Dashboard → Your Project → Deployments
- See all deployments, their status, and logs

### Check Analytics
- Vercel Dashboard → Your Project → Analytics
- See visitor counts, page views, etc.

### View Function Logs
- Deployments → Click a deployment → Functions tab
- See Python serverless function logs
- Useful for debugging API issues

---

## 🆘 Quick Troubleshooting

### App not loading?
1. Check deployment status (should be "Ready")
2. Try hard refresh: `Ctrl + Shift + R` (Windows) or `Cmd + Shift + R` (Mac)
3. Check browser console for errors (F12)

### No data from vendors?
1. Verify API keys are added in Vercel
2. Check they're set to "Production" environment
3. Redeploy after adding keys

### Changes not showing?
1. Confirm you pushed to GitHub
2. Check Vercel deployed the latest commit
3. Clear browser cache

---

## ✅ Deployment Checklist

Use this to ensure everything is done:

- [ ] Code pushed to GitHub
- [ ] `package.json` at repository root
- [ ] `vercel.json` exists
- [ ] `api/` folder with `index.py`
- [ ] Signed into Vercel with GitHub
- [ ] Project imported on Vercel
- [ ] Framework detected: Create React App
- [ ] Environment variables added
- [ ] Clicked "Deploy"
- [ ] Deployment succeeded
- [ ] Visited live URL
- [ ] Tested with sample IOC
- [ ] Results displaying correctly

---

## 🎉 You're Done!

Your SOC IOC Analyzer is now live on the internet!

**Share your URL:**
- With your team
- In your security operations center
- For threat intelligence investigations

**Your live app:**
```
https://[your-project].vercel.app
```

---

## 📚 Additional Resources

- **Vercel Documentation:** https://vercel.com/docs
- **Vercel CLI (optional):** https://vercel.com/docs/cli
- **Support:** https://vercel.com/support

---

## 💡 Pro Tips

1. **Preview Deployments:**
   - Every Git branch gets its own preview URL
   - Perfect for testing before merging to main

2. **Environment Variables per Environment:**
   - Use different keys for Production vs Preview
   - Settings → Environment Variables → Choose environment

3. **Deployment Protection:**
   - Settings → Deployment Protection
   - Password-protect your site if needed

4. **Custom Build Commands:**
   - If needed: Settings → General → Build & Development Settings
   - Override build command if you need custom behavior

---

**Need help?** Refer back to:
- [QUICK_START.md](QUICK_START.md)
- [DETAILED_DEPLOYMENT_STEPS.md](DETAILED_DEPLOYMENT_STEPS.md)
- [FAQ.md](FAQ.md)

Happy deploying! 🚀🛡️
