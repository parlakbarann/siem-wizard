# SIEM Wizard - Project Structure Reference

## Directory Layout

```
siem-wizard/
├── public/               # Frontend assets (publicly accessible)
│   ├── views/           # HTML pages
│   ├── assets/          # Static assets
│   │   ├── css/        # Stylesheets
│   │   └── images/     # Images and logos
│   └── i18n/           # Translations
├── src/                 # Backend utilities
├── api/                 # API endpoint handlers
└── [root files]         # Configuration and main server
```

## Quick Reference

### Frontend Files

| Location | Purpose | Access URL |
|----------|---------|------------|
| `public/views/*.html` | HTML pages | `http://localhost:3000/[page]` |
| `public/assets/css/styles.css` | Main stylesheet | `/assets/css/styles.css` |
| `public/assets/images/*.svg` | Logo files | `/assets/images/[file].svg` |
| `public/i18n/*.json` | Translation files | `/i18n/[lang].json` |

### Backend Files

| Location | Purpose |
|----------|---------|
| `src/database.js` | Database operations (SQLite) |
| `src/auth.js` | JWT authentication |
| `src/crypto-utils.js` | Encryption/decryption |
| `src/api-key-resolver.js` | API key resolution |

### API Endpoints

| File | Endpoint | Method |
|------|----------|--------|
| `api/generate.js` | `/api/generate` | POST |
| `api/optimize.js` | `/api/optimize` | POST |
| `api/rules.js` | `/api/rules` | GET |

### Main Routes (in server.js)

| Route | File | Description |
|-------|------|-------------|
| `/` | `public/views/index.html` | Rule Generator (home) |
| `/catalog` | `public/views/catalog.html` | Rule Catalog |
| `/optimizer` | `public/views/optimizer.html` | Rule Optimizer |
| `/log-analyzer` | `public/views/log-analyzer.html` | Log Analyzer |
| `/rule-tester` | `public/views/rule-tester.html` | Rule Tester |
| `/analytics` | `public/views/analytics.html` | Analytics Dashboard |
| `/history` | `public/views/history.html` | Query History |
| `/settings` | `public/views/settings.html` | User Settings |
| `/login` | `public/views/login.html` | Login Page |
| `/register` | `public/views/register.html` | Registration Page |

## Asset Paths in HTML

When referencing assets in HTML files:

```html
<!-- CSS -->
<link rel="stylesheet" href="/assets/css/styles.css">

<!-- Images -->
<img src="/assets/images/logo.svg" alt="Logo">

<!-- i18n -->
<script src="/i18n/index.js"></script>
```

## Module Imports in Server Files

When importing modules in backend code:

```javascript
// From server.js
const { initDatabase, userDb } = require('./src/database');
const { generateToken, authenticateToken } = require('./src/auth');
const { encryptApiKey, decryptApiKey } = require('./src/crypto-utils');
const { resolveApiKey } = require('./src/api-key-resolver');

// From src/ files (relative imports work)
const { userDb } = require('./database');
const { JWT_SECRET } = require('./auth');
```

## Adding New Files

### New HTML Page
1. Create file in `public/views/[name].html`
2. Add route in `server.js`:
   ```javascript
   app.get('/[route]', (req, res) => {
       res.sendFile(path.join(__dirname, 'public', 'views', '[name].html'));
   });
   ```

### New CSS File
1. Create file in `public/assets/css/[name].css`
2. Reference in HTML:
   ```html
   <link rel="stylesheet" href="/assets/css/[name].css">
   ```

### New Backend Utility
1. Create file in `src/[name].js`
2. Export functions:
   ```javascript
   module.exports = { functionName };
   ```
3. Import in server.js:
   ```javascript
   const { functionName } = require('./src/[name]');
   ```

### New API Endpoint
1. Create file in `api/[name].js`
2. Export handler function
3. Import and use in `server.js`:
   ```javascript
   const { handlerName } = require('./api/[name]');
   app.post('/api/[endpoint]', handlerName);
   ```

## Development Commands

```bash
# Start development server
npm start

# Test server
curl http://localhost:3000/api/health

# View server logs
npm start | grep "Error"
```

## File Naming Conventions

- HTML files: `kebab-case.html` (e.g., `log-analyzer.html`)
- JavaScript files: `kebab-case.js` (e.g., `api-key-resolver.js`)
- CSS files: `kebab-case.css` (e.g., `styles.css`)
- Image files: `kebab-case.svg` (e.g., `logo-simple.svg`)

## Important Notes

1. All static files are served from `public/` directory
2. Never hardcode absolute paths in HTML (use `/assets/...`)
3. Backend modules use relative imports (`./src/...`)
4. i18n files are loaded dynamically from `/i18n/`
5. Database file (`users.db`) stays in project root

## Troubleshooting

**Assets not loading?**
- Check the path starts with `/assets/` or `/i18n/`
- Verify file exists in correct `public/` subdirectory

**Module not found?**
- Check require path uses `./src/` for backend utilities
- Verify file exists in `src/` directory

**Page not rendering?**
- Check route handler in `server.js`
- Verify HTML file exists in `public/views/`

---

Last updated: 2026-01-05
