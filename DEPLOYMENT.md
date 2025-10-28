# Deployment Guide

This guide covers how to deploy the Suspicious Login Detector to various hosting platforms.

## 🚀 Quick Deploy Options

### 1. Vercel (Recommended - Free)

**One-click deploy:**
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/AydanK78/suspicious-login-detector)

**Manual deployment:**
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Follow the prompts
```

### 2. Railway (Full-stack hosting)

**One-click deploy:**
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/your-template-id)

**Manual deployment:**
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

### 3. Render (Free tier available)

1. Connect your GitHub repository
2. Select "Web Service"
3. Build command: `npm run build`
4. Start command: `npm start`
5. Add environment variable: `NODE_ENV=production`

### 4. Heroku

```bash
# Install Heroku CLI
# Create Procfile
echo "web: npm start" > Procfile

# Deploy
git add .
git commit -m "Add Procfile"
heroku create your-app-name
git push heroku main
```

## 🔧 Environment Variables

Set these in your hosting platform:

```env
NODE_ENV=production
PORT=3000
```

## 📊 Database Considerations

### SQLite (Default)
- ✅ Works out of the box
- ✅ No additional setup
- ❌ Data lost on server restart (free tiers)

### PostgreSQL (Production)
For persistent data, add PostgreSQL:

```bash
# Install PostgreSQL driver
npm install pg @types/pg

# Update database.ts to use PostgreSQL
# Add connection string to environment variables
DATABASE_URL=postgresql://user:password@host:port/database
```

## 🌐 Domain Setup

### Custom Domain (Vercel)
1. Go to your project settings
2. Add your domain in "Domains" section
3. Update DNS records as instructed

### Subdomain (Railway)
1. Go to project settings
2. Add custom domain
3. Update DNS to point to Railway

## 📱 Mobile App (Optional)

The dashboard is fully responsive and works on mobile devices. For a native app:

1. **React Native**: Use the existing API endpoints
2. **Flutter**: Create a Flutter app that calls the REST API
3. **PWA**: Add a service worker for offline functionality

## 🔒 Security Considerations

### Production Checklist
- [ ] Change default risk thresholds
- [ ] Set up proper CORS policies
- [ ] Add rate limiting
- [ ] Enable HTTPS
- [ ] Set up monitoring and alerts
- [ ] Regular database backups

### Environment Security
```env
# Production settings
NODE_ENV=production
CORS_ORIGIN=https://yourdomain.com
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
```

## 📈 Monitoring & Analytics

### Built-in Monitoring
- Real-time dashboard
- System health indicators
- Risk level tracking
- User activity logs

### External Monitoring
- **Uptime monitoring**: UptimeRobot, Pingdom
- **Error tracking**: Sentry, Bugsnag
- **Analytics**: Google Analytics, Mixpanel

## 🚨 Alerts & Notifications

### Email Alerts
```javascript
// Add to detector.ts
if (assessment.riskLevel === 'critical') {
  await sendEmailAlert(assessment);
}
```

### Webhook Notifications
```javascript
// Add webhook support
if (assessment.riskLevel === 'high' || assessment.riskLevel === 'critical') {
  await sendWebhook(assessment);
}
```

## 🔄 CI/CD Pipeline

### GitHub Actions
```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm install
      - run: npm run build
      - run: npm test
      - run: vercel --prod
```

## 📋 Pre-deployment Checklist

- [ ] All tests passing
- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] Security settings reviewed
- [ ] Performance optimized
- [ ] Documentation updated
- [ ] Monitoring configured

## 🆘 Troubleshooting

### Common Issues

**Build fails:**
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
npm run build
```

**Database errors:**
```bash
# Check database file permissions
ls -la suspicious_logins.db
chmod 664 suspicious_logins.db
```

**WebSocket not working:**
- Check if hosting platform supports WebSockets
- Verify CORS settings
- Check firewall rules

### Support

- 📖 [Documentation](README.md)
- 🐛 [Issues](https://github.com/AydanK78/suspicious-login-detector/issues)
- 💬 [Discussions](https://github.com/AydanK78/suspicious-login-detector/discussions)

## 🎯 Next Steps

After deployment:

1. **Test the dashboard**: Visit your deployed URL
2. **Configure monitoring**: Set up alerts for critical events
3. **Customize settings**: Adjust risk thresholds for your use case
4. **Add integrations**: Connect to your existing systems
5. **Scale up**: Consider database upgrades for high traffic

---

**Your Suspicious Login Detector is ready for production! 🚀**
