# Vercel Deployment Guide - SOC IOC Analyzer

## ✅ Project Structure is Ready!

Your project has been restructured and is now **Vercel-ready**. The structure looks like this:

```
/app/
├── api/                      # FastAPI serverless function
│   ├── index.py              # Main backend API
│   └── requirements.txt      # Python dependencies
├── public/                   # Static assets
│   └── index.html
├── src/                      # React source code
│   ├── App.js                # Main React component
│   ├── components/           # UI components
│   └── ...
├── package.json              # ✅ At ROOT (critical for Vercel)
├── vercel.json               # Vercel configuration
└── ... (other config files)
```

## 📦 Step-by-Step Deployment Instructions

### Step 1: Push to GitHub

1. **Commit all changes:**
   ```bash
   git add .
   git commit -m "Restructure for Vercel deployment"
   ```

2. **Push to GitHub:**
   - If you have an existing repository, push to it:
     ```bash
     git push origin main
     ```
   
   - If this is a new repository, create one on GitHub first, then:
     ```bash
     git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
     git branch -M main
     git push -u origin main
     ```

### Step 2: Deploy on Vercel

1. **Go to Vercel:**
   - Visit: https://vercel.com
   - Sign in with your GitHub account

2. **Import Project:**
   - Click "Add New..." → "Project"
   - Select your GitHub repository from the list
   - Click "Import"

3. **Configure Project (IMPORTANT!):**
   
   Vercel should auto-detect the configuration, but verify these settings:
   
   - **Framework Preset:** Create React App
   - **Root Directory:** `./` (leave as default)
   - **Build Command:** `npm run build` (auto-detected from package.json)
   - **Output Directory:** `build` (auto-detected)

4. **Add Environment Variables:**
   
   Before clicking "Deploy", scroll down to "Environment Variables" and add these API keys:
   
   ```
   ABUSEIPDB_API_KEY          = your_key_here
   VIRUSTOTAL_API_KEY         = your_key_here
   URLSCAN_API_KEY            = your_key_here
   ALIENVAULT_API_KEY         = your_key_here
   GREYNOISE_API_KEY          = your_key_here
   ```
   
   **Note:** If you don't have all API keys right now, you can:
   - Deploy without them (the app will work, but some integrations won't return data)
   - Add them later via: Project Settings → Environment Variables → Add

5. **Deploy:**
   - Click "Deploy"
   - Wait 2-3 minutes for the build to complete
   - You'll get a live URL like: `https://your-project.vercel.app`

### Step 3: Test Your Deployment

1. Visit your Vercel URL
2. Try analyzing an IOC (e.g., IP address: `8.8.8.8`)
3. Check if results are displayed correctly

## 🔑 Where to Get API Keys

If you don't have API keys yet, here's where to get them:

1. **AbuseIPDB:** https://www.abuseipdb.com/api
   - Free tier: 1,000 requests/day
   
2. **VirusTotal:** https://www.virustotal.com/gui/join-us
   - Free tier: 500 requests/day
   
3. **URLScan:** https://urlscan.io/about/api/
   - Free tier available
   
4. **AlienVault OTX:** https://otx.alienvault.com/api
   - Create account → Settings → API Key
   
5. **GreyNoise:** https://www.greynoise.io/
   - Free community tier available

## 🔄 Updating Your Deployment

After making code changes:

```bash
git add .
git commit -m "Your update message"
git push origin main
```

Vercel will automatically redeploy!

## 🐛 Troubleshooting

### Build fails with "ENOENT: no such file or directory, open '/vercel/path0/package.json'"
- **Solution:** This was the original issue. It's now FIXED! The package.json is at the root.

### API calls return errors
- **Check:** Make sure you've added the environment variables in Vercel
- **Location:** Project Settings → Environment Variables

### Frontend loads but no data
- **Check:** Browser console for errors
- **Solution:** Verify API keys are correct in Vercel settings

### Python dependencies fail to install
- **Check:** The `api/requirements.txt` file
- **Solution:** Ensure all packages are listed correctly (they are!)

## 📝 Notes

- The application is **stateless** (no database required)
- All API calls are made directly to third-party services
- The backend runs as a serverless function on Vercel
- CORS is configured to accept all origins (safe for public API)

## ✨ You're All Set!

Your project is now properly structured for Vercel. Just follow the steps above and you'll have a live deployment in minutes!

**Questions?** Double-check the environment variables in Vercel settings - that's the most common issue after deployment.
