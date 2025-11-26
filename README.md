# 🛡️ SOC IOC Analyzer - Vercel Deployment

> **✅ PROJECT STRUCTURE IS READY FOR DEPLOYMENT!**  
> This repository is now correctly configured for Vercel. Just push to GitHub and deploy!

## 🚀 Quick Deploy to Vercel (3 Easy Steps)

### Step 1: Push to GitHub

If you already have a GitHub repository:
```bash
git add .
git commit -m "Vercel-ready structure"
git push origin main
```

If this is a new repository:
```bash
git init
git add .
git commit -m "Initial commit - SOC IOC Analyzer"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/soc-ioc-analyzer.git
git push -u origin main
```

### Step 2: Deploy on Vercel

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New..."** → **"Project"**
3. Select your `soc-ioc-analyzer` repository
4. **Add Environment Variables** (before deploying):
   - Click **"Environment Variables"** section
   - Add these keys (get them from the providers listed below):

   | Name | Required | Get It From |
   |------|----------|-------------|
   | `ABUSEIPDB_API_KEY` | Recommended | [abuseipdb.com/api](https://www.abuseipdb.com/api) |
   | `VIRUSTOTAL_API_KEY` | Recommended | [virustotal.com](https://www.virustotal.com/gui/join-us) |
   | `URLSCAN_API_KEY` | Optional | [urlscan.io/api](https://urlscan.io/about/api/) |
   | `ALIENVAULT_API_KEY` | Optional | [otx.alienvault.com](https://otx.alienvault.com/api) |
   | `GREYNOISE_API_KEY` | Optional | [greynoise.io](https://www.greynoise.io/) |

5. Click **"Deploy"**
6. Wait 2-3 minutes for build to complete

### Step 3: Test Your Deployment

Visit your live URL (e.g., `https://your-project.vercel.app`) and try analyzing:
- **IP Address:** `8.8.8.8`
- **Domain:** `example.com`
- **Email:** `test@example.com`
- **Hash:** Any MD5/SHA1/SHA256 hash

## 📚 Documentation

- **[DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)** - Comprehensive deployment instructions
- **[PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md)** - Understanding the file structure

## 🔑 Getting API Keys (Free Tiers Available)

1. **AbuseIPDB** (1,000 requests/day): https://www.abuseipdb.com/api
2. **VirusTotal** (500 requests/day): https://www.virustotal.com/gui/join-us
3. **URLScan** (Free tier): https://urlscan.io/about/api/
4. **AlienVault OTX** (Free): https://otx.alienvault.com/api
5. **GreyNoise** (Community tier): https://www.greynoise.io/

## 🔄 Updating Your Deployment

After making code changes:
```bash
git add .
git commit -m "Your update message"
git push origin main
```

Vercel will automatically rebuild and redeploy!

## 🎯 What This Tool Does

**SOC IOC Analyzer** helps security analysts investigate Indicators of Compromise (IOCs) by:

- **Auto-detecting** IOC types (IPs, domains, URLs, emails, hashes)
- **Multi-vendor analysis** from 11 threat intelligence sources
- **Threat scoring** with confidence levels
- **Email header analysis** for phishing investigations
- **Domain security checks** (SPF, DMARC, MX records)

## 📦 Tech Stack

- **Frontend:** React + Tailwind CSS + Shadcn UI
- **Backend:** FastAPI (Python serverless function)
- **Deployment:** Vercel (serverless)
- **APIs:** AbuseIPDB, VirusTotal, URLScan, AlienVault OTX, GreyNoise, Shodan, and more

## ✅ Ready to Go!

Your project structure is correct and Vercel-compatible. Follow the 3 steps above and you'll be live in minutes! 🎉

---

**Questions?** Check the [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) for detailed troubleshooting.
