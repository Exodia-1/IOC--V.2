# SOC IOC Analyzer - Vercel Deployment

## Quick Deploy to Vercel (FREE)

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "SOC IOC Analyzer"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/soc-ioc-analyzer.git
git push -u origin main
```

### Step 2: Deploy on Vercel
1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New Project"**
3. Import your `soc-ioc-analyzer` repository
4. Click **"Deploy"** (uses default settings)

### Step 3: Add Environment Variables
After first deploy, go to **Project Settings** > **Environment Variables** and add:

| Name | Value |
|------|-------|
| ABUSEIPDB_API_KEY | your-key |
| VIRUSTOTAL_API_KEY | your-key |
| URLSCAN_API_KEY | your-key |
| ALIENVAULT_API_KEY | your-key |
| GREYNOISE_API_KEY | your-key |

Then click **Redeploy** from Deployments tab.

### Done!
Your app will be live at `https://your-project.vercel.app`
