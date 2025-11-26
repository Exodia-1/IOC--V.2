# 🚀 Complete Step-by-Step Deployment Guide

## Before You Start

✅ Your project structure is **READY**  
✅ All files are in the correct locations  
✅ You just need to push to GitHub and deploy!

---

## Part 1: Push to GitHub (5 minutes)

### Option A: If You Already Have a GitHub Repository

1. **Open Terminal/Command Prompt** and navigate to your project:
   ```bash
   cd /app
   ```

2. **Check current status:**
   ```bash
   git status
   ```
   You should see all your files ready.

3. **Add all changes:**
   ```bash
   git add .
   ```

4. **Commit the changes:**
   ```bash
   git commit -m "Fix Vercel structure - ready for deployment"
   ```

5. **Push to GitHub:**
   ```bash
   git push origin main
   ```
   
   If your default branch is `master` instead of `main`:
   ```bash
   git push origin master
   ```

6. **Verify:** Go to your GitHub repository URL in a browser and confirm you see:
   - `package.json` at the root level
   - `api/` folder
   - `src/` folder
   - `vercel.json`

---

### Option B: If You Need to Create a New GitHub Repository

1. **Go to GitHub:**
   - Open https://github.com in your browser
   - Sign in to your account

2. **Create New Repository:**
   - Click the **"+"** icon (top right) → **"New repository"**
   - Repository name: `soc-ioc-analyzer` (or any name you prefer)
   - Description: "SOC IOC Analysis Tool"
   - Choose **Public** or **Private** (your choice)
   - **DO NOT** check "Add a README file"
   - **DO NOT** check "Add .gitignore"
   - Click **"Create repository"**

3. **Push Your Code:**
   GitHub will show you commands. Use these in your terminal:

   ```bash
   cd /app
   git remote add origin https://github.com/YOUR_USERNAME/soc-ioc-analyzer.git
   git branch -M main
   git push -u origin main
   ```
   
   Replace `YOUR_USERNAME` with your actual GitHub username.

4. **Enter Credentials:**
   - GitHub may ask for your username and password
   - **Note:** For password, you need a **Personal Access Token** (not your regular password)
   - If you don't have a token, go to: GitHub → Settings → Developer settings → Personal access tokens → Generate new token (classic) → Select "repo" scope → Generate

5. **Verify:** Refresh your GitHub repository page. You should see all your files!

---

## Part 2: Deploy on Vercel (10 minutes)

### Step 1: Sign Up / Sign In to Vercel

1. **Go to Vercel:**
   - Open https://vercel.com in your browser

2. **Sign In with GitHub:**
   - Click **"Sign Up"** (if new) or **"Log In"** (if you have an account)
   - Choose **"Continue with GitHub"**
   - Authorize Vercel to access your GitHub account
   - Click **"Authorize Vercel"**

---

### Step 2: Import Your Project

1. **From Vercel Dashboard:**
   - You'll see your dashboard after signing in
   - Click **"Add New..."** button (top right)
   - Select **"Project"** from dropdown

2. **Import Git Repository:**
   - You'll see a list of your GitHub repositories
   - Find **"soc-ioc-analyzer"** (or whatever you named it)
   - Click **"Import"** next to it

   **Can't see your repository?**
   - Click **"Adjust GitHub App Permissions"**
   - Select which repositories Vercel can access
   - Choose "All repositories" or select specific ones
   - Save

---

### Step 3: Configure Project Settings

After clicking Import, you'll see the **"Configure Project"** page:

1. **Project Name:**
   - Vercel auto-fills this (e.g., `soc-ioc-analyzer`)
   - You can change it if you want
   - This will be part of your URL: `https://PROJECT-NAME.vercel.app`

2. **Framework Preset:**
   - Vercel should auto-detect **"Create React App"**
   - If not, select it from the dropdown

3. **Root Directory:**
   - Leave as **"./"** (default)
   - This means the root of your repository

4. **Build and Output Settings:**
   - **Build Command:** `npm run build` (auto-detected)
   - **Output Directory:** `build` (auto-detected)
   - **Install Command:** `npm install` (auto-detected)
   - **DO NOT** change these unless you know what you're doing

---

### Step 4: Add Environment Variables (IMPORTANT!)

**Before deploying**, scroll down to the **"Environment Variables"** section:

1. **Click** "Environment Variables" to expand it

2. **Add each API key one by one:**

   **For AbuseIPDB:**
   - **Key:** `ABUSEIPDB_API_KEY`
   - **Value:** Paste your API key (get from https://www.abuseipdb.com/api)
   - Click **"Add"**

   **For VirusTotal:**
   - **Key:** `VIRUSTOTAL_API_KEY`
   - **Value:** Paste your API key (get from https://www.virustotal.com/gui/join-us)
   - Click **"Add"**

   **For URLScan:**
   - **Key:** `URLSCAN_API_KEY`
   - **Value:** Paste your API key (get from https://urlscan.io/about/api/)
   - Click **"Add"**

   **For AlienVault:**
   - **Key:** `ALIENVAULT_API_KEY`
   - **Value:** Paste your API key (get from https://otx.alienvault.com/api)
   - Click **"Add"**

   **For GreyNoise:**
   - **Key:** `GREYNOISE_API_KEY`
   - **Value:** Paste your API key (get from https://www.greynoise.io/)
   - Click **"Add"**

3. **Environment:** Make sure "Production" is selected for each variable

**Don't have all API keys yet?**
- You can skip some and add them later
- The app will still work with the keys you have
- You can add more keys later in: Project Settings → Environment Variables

---

### Step 5: Deploy!

1. **Review your settings:**
   - Framework: Create React App ✓
   - Build Command: npm run build ✓
   - Output Directory: build ✓
   - Environment Variables: Added ✓

2. **Click the big blue "Deploy" button**

3. **Wait for deployment:**
   - You'll see a build log with real-time progress
   - This takes about **2-3 minutes**
   - You'll see steps like:
     - Installing dependencies
     - Building React app
     - Setting up Python serverless function
     - Optimizing files

4. **Watch for:**
   - ✅ Green checkmarks = success
   - ❌ Red X = error (see troubleshooting below)

---

### Step 6: Success! 🎉

When deployment finishes successfully:

1. **You'll see a congratulations screen** with:
   - 🎊 Confetti animation
   - Your live URL (e.g., `https://soc-ioc-analyzer-abc123.vercel.app`)
   - A preview image of your site

2. **Click "Visit"** or click on the URL

3. **Your app is LIVE!**

---

## Part 3: Test Your Deployment (2 minutes)

### Test 1: Homepage Loads

1. Visit your Vercel URL
2. You should see:
   - "SOC IOC Analyzer" title
   - Input field for IOCs
   - Tabs for Single/Bulk/Email analysis

**Issue?** If page doesn't load, check browser console (F12) for errors.

---

### Test 2: Analyze an IP Address

1. **In the input field, enter:** `8.8.8.8`
2. **Click** "Analyze IOC"
3. **Wait** 5-10 seconds
4. **You should see results from:**
   - VirusTotal
   - AbuseIPDB
   - GreyNoise
   - Shodan
   - IPInfo
   - WHOIS
   - And more!

**No results?** Check if you added the API keys correctly.

---

### Test 3: Analyze a Domain

1. **Enter:** `google.com`
2. **Click** "Analyze IOC"
3. **Check results** from multiple vendors

---

### Test 4: Analyze an Email

1. **Enter:** `test@gmail.com`
2. **Click** "Analyze IOC"
3. **Check** email domain analysis and MX records

---

### Test 5: Email Header Analysis

1. **Click** the "Email Headers" tab
2. **Paste sample email headers** (you can use any email's raw headers)
3. **Click** "Analyze Headers"
4. **Check** for security analysis results

---

## Part 4: Adding/Updating Environment Variables Later

If you need to add API keys later:

1. **Go to Vercel Dashboard:** https://vercel.com/dashboard
2. **Click** on your project (`soc-ioc-analyzer`)
3. **Click** "Settings" tab (top menu)
4. **Click** "Environment Variables" (left sidebar)
5. **Add new variables:**
   - Enter Key name
   - Enter Value
   - Select "Production" environment
   - Click "Save"
6. **Redeploy:**
   - Go to "Deployments" tab
   - Click "..." on the latest deployment
   - Click "Redeploy"
   - Wait for redeployment to finish

---

## Part 5: Custom Domain (Optional)

Want to use your own domain instead of `.vercel.app`?

1. **From Project Dashboard:**
   - Click "Settings" tab
   - Click "Domains" (left sidebar)

2. **Add Your Domain:**
   - Enter your domain (e.g., `ioc-analyzer.com`)
   - Click "Add"

3. **Configure DNS:**
   - Vercel will show you DNS records to add
   - Go to your domain registrar (GoDaddy, Namecheap, etc.)
   - Add the DNS records Vercel provides
   - Wait for DNS propagation (can take up to 48 hours)

4. **Verify:**
   - Once DNS is configured, your site will be accessible at your custom domain!

---

## Troubleshooting Common Issues

### Issue 1: "ENOENT: no such file or directory, open '/vercel/path0/package.json'"

**Solution:** This was the original error. It's FIXED now! But if you still see it:
- Make sure you pushed the LATEST code to GitHub
- Verify `package.json` is at the root of your repository (not in a subfolder)
- In Vercel settings, make sure "Root Directory" is set to `./`

---

### Issue 2: Build Fails with "npm ERR! code ERESOLVE"

**Solution:**
- This is a dependency conflict
- Vercel should handle this automatically with `--legacy-peer-deps`
- If it persists, add this to Vercel settings:
  - Settings → General → Build & Development Settings
  - Override Install Command: `npm install --legacy-peer-deps`

---

### Issue 3: "Module not found" Errors

**Solution:**
- Make sure all imports in your React code use correct paths
- The current code uses `@/` alias (configured in jsconfig.json)
- All imports should work correctly as-is

---

### Issue 4: API Returns No Data

**Causes:**
- API keys not configured
- API keys are invalid
- Rate limits reached on free tiers

**Solution:**
1. Go to Vercel → Project → Settings → Environment Variables
2. Verify all keys are correct
3. Test each API key individually:
   - AbuseIPDB: Try analyzing an IP
   - VirusTotal: Try analyzing any IOC
4. Check the Vercel Functions logs:
   - Deployments tab → Click latest deployment → "Functions" tab
   - Look for errors related to API calls

---

### Issue 5: "504 Gateway Timeout"

**Causes:**
- Python serverless function taking too long (>10 seconds on free tier)
- External API calls timing out

**Solution:**
- This is usually temporary
- Try again in a few seconds
- If persistent, check if external APIs are down

---

### Issue 6: Can't See My Repository in Vercel

**Solution:**
1. Click "Adjust GitHub App Permissions"
2. Grant Vercel access to your repository
3. Or choose "All repositories" to give full access

---

## Quick Reference: Where Everything Is

| What You Need | Where to Find It |
|---------------|------------------|
| Vercel Dashboard | https://vercel.com/dashboard |
| Your Live URL | Dashboard → Click your project name |
| Environment Variables | Project → Settings → Environment Variables |
| Deployment Logs | Project → Deployments → Click a deployment |
| Domain Settings | Project → Settings → Domains |
| Function Logs | Deployments → Functions tab |
| Redeploy | Deployments → "..." → Redeploy |

---

## Next Steps After Deployment

### 1. Share Your App
- Your URL: `https://your-project.vercel.app`
- Share it with your team or colleagues
- Use it for SOC investigations

### 2. Make Updates
When you want to add features or fix bugs:
```bash
# Make your changes in code
git add .
git commit -m "Description of changes"
git push origin main
```
Vercel will **automatically redeploy**!

### 3. Monitor Usage
- Check Vercel dashboard for:
  - Number of visits
  - Function execution times
  - Bandwidth usage
  - Build times

### 4. Upgrade if Needed
Free tier includes:
- ✅ Unlimited personal projects
- ✅ 100GB bandwidth/month
- ✅ Serverless function execution
- ✅ Automatic HTTPS

Paid plans offer:
- More bandwidth
- Longer function execution times
- Team collaboration
- Priority support

---

## Summary Checklist

Before you start:
- [ ] Code is ready in `/app` directory
- [ ] You have a GitHub account

Part 1 - GitHub:
- [ ] Created/selected GitHub repository
- [ ] Pushed code to GitHub
- [ ] Verified files are visible on GitHub

Part 2 - Vercel:
- [ ] Signed in to Vercel with GitHub
- [ ] Imported your repository
- [ ] Configured project settings
- [ ] Added environment variables (API keys)
- [ ] Clicked Deploy button
- [ ] Deployment succeeded

Part 3 - Testing:
- [ ] Visited live URL
- [ ] Tested IP analysis
- [ ] Tested domain analysis
- [ ] Tested email analysis
- [ ] All features working

---

## 🎉 Congratulations!

Your SOC IOC Analyzer is now live on the internet! You can access it from anywhere, share it with colleagues, and use it for real security investigations.

**Your accomplishment:**
✅ Converted a local app to a serverless cloud application  
✅ Set up automated deployments (push to deploy)  
✅ Integrated with 11 threat intelligence APIs  
✅ Deployed a full-stack app (React + Python) on Vercel  

**Questions or issues?** Review the troubleshooting section above or let me know!
