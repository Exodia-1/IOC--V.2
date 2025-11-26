# ❓ Frequently Asked Questions (FAQ)

## General Questions

### Q1: What is this project?
**A:** SOC IOC Analyzer is a web-based tool for Security Operations Center (SOC) analysts to investigate Indicators of Compromise (IOCs). It automatically detects IOC types (IPs, domains, URLs, emails, hashes) and queries multiple threat intelligence sources to provide comprehensive security analysis.

### Q2: Is it free to deploy?
**A:** Yes! Both GitHub and Vercel offer free tiers:
- **GitHub:** Free unlimited public/private repositories
- **Vercel:** Free for personal projects with generous limits:
  - Unlimited deployments
  - 100GB bandwidth/month
  - Automatic HTTPS
  - Serverless functions included

### Q3: Do I need to pay for API keys?
**A:** Most threat intelligence APIs offer free tiers:
- AbuseIPDB: 1,000 requests/day (free)
- VirusTotal: 500 requests/day (free)
- URLScan: Free tier available
- AlienVault OTX: Free
- GreyNoise: Community tier (free)
- Shodan: Free API (limited)
- IPInfo: Free

For heavy usage, paid plans are available, but the free tiers are sufficient for most use cases.

---

## Deployment Questions

### Q4: Why was my original deployment failing?
**A:** The error `ENOENT: no such file or directory, open '/vercel/path0/package.json'` occurred because:
- Vercel expects `package.json` at the repository root
- Your original structure had it inside a `frontend/` subfolder
- Vercel couldn't find it, so the build failed

**This is now FIXED!** The structure has been corrected.

### Q5: How long does deployment take?
**A:**
- **First deployment:** ~10-12 minutes (including setup)
- **Future deployments:** ~2-3 minutes (just `git push`)
- **Build time:** ~2-3 minutes each time

### Q6: What happens if I push code changes?
**A:** Vercel automatically detects changes and redeploys:
1. You push to GitHub: `git push origin main`
2. Vercel receives webhook notification
3. Vercel starts building automatically
4. New version goes live in 2-3 minutes
5. Old version is replaced

### Q7: Can I roll back to a previous version?
**A:** Yes! In Vercel:
1. Go to "Deployments" tab
2. Find the deployment you want to restore
3. Click "..." menu → "Promote to Production"
4. That version becomes live immediately

---

## Technical Questions

### Q8: What technology stack is this using?
**A:** 
- **Frontend:** React 18, Tailwind CSS, Shadcn UI components
- **Backend:** FastAPI (Python), running as Vercel serverless function
- **Deployment:** Vercel (serverless platform)
- **APIs:** 11 threat intelligence sources
- **No database:** Application is stateless

### Q9: Is there a database?
**A:** No, this application is **stateless**:
- No data is stored permanently
- Each analysis is done in real-time
- Results are displayed but not saved
- This keeps costs at $0 and simplifies deployment

### Q10: How does the frontend communicate with the backend?
**A:**
- Frontend makes HTTP requests to `/api/*` routes
- Vercel routes all `/api/*` requests to the Python serverless function
- The Python function processes requests and calls external APIs
- Results are returned as JSON to the frontend
- React displays the results

### Q11: Can I run this locally for development?
**A:** Yes! The original structure supports local development:
```bash
# Frontend (in one terminal)
cd frontend
npm start

# Backend (in another terminal)
cd backend
uvicorn server:app --reload --port 8001
```

But the deployed version on Vercel uses the serverless architecture.

---

## API & Integration Questions

### Q12: What if I don't have all API keys?
**A:** The app still works! Each vendor integration is independent:
- If you have VirusTotal key: VirusTotal results appear
- If you don't have GreyNoise key: GreyNoise section shows "No key configured"
- Other services continue to work normally

Some services don't require keys:
- Shodan (uses free public API)
- IPInfo (limited free access)
- WHOIS lookups
- DNS queries (MXToolbox)

### Q13: How do I add API keys after deployment?
**A:**
1. Go to Vercel Dashboard
2. Click your project
3. Settings → Environment Variables
4. Click "Add" to add new variables
5. Enter key name and value
6. Click "Save"
7. Go to Deployments → Latest deployment → "..." → "Redeploy"

### Q14: Are my API keys secure?
**A:** Yes:
- Keys are stored as environment variables in Vercel
- They're never exposed to the frontend/browser
- They're only accessible to the serverless function
- HTTPS encrypts all communication
- Keys are not visible in your code or logs

### Q15: What if an API key reaches its rate limit?
**A:** The app handles this gracefully:
- That specific vendor will return an error
- Other vendors continue to work
- Frontend displays "Rate limit exceeded" for that vendor
- No app crash or failure

---

## Customization Questions

### Q16: Can I add more threat intelligence sources?
**A:** Yes! Edit `api/index.py`:
1. Add a new `async def query_VENDOR(...)` function
2. Add it to the task list in the analyze endpoint
3. Update the frontend to display results
4. Redeploy

### Q17: Can I change the app's appearance?
**A:** Yes! The UI uses Tailwind CSS:
- Edit `src/App.js` for structure
- Modify Tailwind classes for styling
- Edit `tailwind.config.js` for theme changes
- Changes take effect after redeployment

### Q18: Can I add user authentication?
**A:** Yes, but requires modifications:
- Add an auth provider (Auth0, Firebase, etc.)
- Add login/signup UI components
- Protect routes in React
- Add authentication middleware to backend
- Consider adding a database to store user data

### Q19: Can I save analysis results?
**A:** Not currently, but you can add this:
- Add a database (MongoDB, PostgreSQL, etc.)
- Create "Save Analysis" button in UI
- Store results with timestamp and user ID
- Create "History" page to view past analyses

### Q20: Can I add more IOC types?
**A:** Yes! Edit `api/index.py`:
1. Add regex pattern to `IOC_PATTERNS` dict
2. Update `detect_ioc_type()` function
3. Add appropriate vendor query functions
4. Update frontend to handle new type

---

## Vercel-Specific Questions

### Q21: What is a Vercel serverless function?
**A:** Your Python backend runs "on-demand":
- No server running 24/7
- Function starts when someone makes a request
- Executes your code
- Returns result
- Shuts down after execution
- You only "pay" for execution time (free tier includes this)

### Q22: What are Vercel's limits on the free tier?
**A:**
- **Deployments:** Unlimited
- **Bandwidth:** 100GB/month
- **Function execution:** 100 hours/month
- **Function duration:** 10 seconds max per request
- **Build time:** 45 minutes max
- **Commercial use:** Not allowed on free tier

### Q23: What happens if I exceed the free tier limits?
**A:**
- Vercel will send you email notifications
- Your site might be temporarily paused
- You can upgrade to Pro plan (~$20/month)
- Or optimize to stay within limits

### Q24: Can I use a custom domain?
**A:** Yes! (Free on Vercel)
1. Settings → Domains
2. Add your domain
3. Configure DNS at your registrar
4. Vercel handles HTTPS automatically

### Q25: How do I see logs and errors?
**A:**
- **Build logs:** Deployments tab → Click deployment → View logs
- **Runtime logs:** Deployments → Functions tab
- **Error tracking:** Consider adding Sentry or similar

---

## Troubleshooting Questions

### Q26: My deployment succeeded but the page is blank
**Possible causes:**
1. JavaScript error in browser (check Console with F12)
2. API endpoint misconfigured
3. Missing environment variable

**Fix:**
- Check browser console for errors
- Verify API calls are going to `/api/*` routes
- Check Vercel Function logs

### Q27: I see "Module not found" error
**Cause:** Missing dependency or wrong import path

**Fix:**
1. Check `package.json` includes the package
2. Verify import paths use `@/` alias correctly
3. Make sure `jsconfig.json` exists

### Q28: API calls return 500 errors
**Possible causes:**
1. Python dependency missing in `api/requirements.txt`
2. API key invalid or missing
3. External API is down
4. Serverless function timeout (>10 seconds)

**Fix:**
- Check Vercel Function logs for specific error
- Verify API keys are correct
- Test external APIs manually

### Q29: "This Serverless Function has crashed"
**Cause:** Python error in backend code

**Fix:**
1. Go to Deployments → Functions tab
2. Find the error message
3. Fix the code issue
4. Redeploy

### Q30: Changes aren't showing up after redeployment
**Cause:** Browser caching

**Fix:**
- Hard refresh: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)
- Clear browser cache
- Try incognito/private mode
- Check if deployment actually completed

---

## Performance Questions

### Q31: How fast are the IOC lookups?
**A:** Depends on external APIs:
- Fastest: ~2-3 seconds (all APIs respond quickly)
- Average: ~5-7 seconds (some APIs slower)
- Slowest: ~10 seconds (rate limiting or slow responses)

The backend queries all APIs in parallel for maximum speed.

### Q32: Can I improve performance?
**Yes:**
- Cache results (requires database)
- Reduce number of APIs queried
- Upgrade Vercel plan for faster functions
- Use paid API tiers for faster responses

### Q33: How many requests can it handle?
**A:**
- Vercel scales automatically
- Can handle thousands of concurrent users
- Limited by:
  - External API rate limits
  - Vercel free tier function hours
  - Your API key quotas

---

## Cost Questions

### Q34: Is this really free?
**A:** Yes, with the free tiers:
- **GitHub:** Free forever
- **Vercel:** Free for personal use
- **API keys:** Free tiers available
- **Total cost:** $0/month

### Q35: When would I need to pay?
**You'd need paid plans if:**
- Bandwidth exceeds 100GB/month
- Commercial/business use
- Need custom features (teams, SSO, etc.)
- Want longer function execution times
- External APIs exceed free tier quotas

### Q36: How much would paid plans cost?
**A:**
- **Vercel Pro:** $20/month (400GB bandwidth, more features)
- **VirusTotal:** From $144/month (10K requests/day)
- **AbuseIPDB:** From $25/month (10K requests/day)
- **Other APIs:** Varies by provider

Most personal/small team use cases stay within free tiers.

---

## Next Steps Questions

### Q37: What should I do after deployment?
**A:**
1. Test all features thoroughly
2. Share URL with colleagues
3. Monitor usage in Vercel dashboard
4. Add more API keys if needed
5. Consider customizations

### Q38: How do I get help if stuck?
**A:**
1. Check this FAQ
2. Read DEPLOYMENT_GUIDE.md
3. Check DETAILED_DEPLOYMENT_STEPS.md
4. Review Vercel documentation: https://vercel.com/docs
5. Check Vercel community forum
6. Review error messages carefully

### Q39: Can I contribute to improving this project?
**A:** Absolutely! You can:
- Add more threat intelligence sources
- Improve UI/UX
- Add new features (save results, history, etc.)
- Add user authentication
- Create API documentation
- Write tests

### Q40: Where can I learn more?
**A:**
- **React:** https://react.dev
- **FastAPI:** https://fastapi.tiangolo.com
- **Vercel:** https://vercel.com/docs
- **Tailwind CSS:** https://tailwindcss.com
- **Threat Intelligence:** MITRE ATT&CK, NIST guidelines

---

## 🎯 Still Have Questions?

If your question isn't answered here:
1. Check the other documentation files in this repository
2. Review Vercel's documentation
3. Check the browser console and Vercel logs for specific errors
4. Search Vercel's community forums
5. Let me know and I can help!

---

**Happy Investigating! 🔍🛡️**
