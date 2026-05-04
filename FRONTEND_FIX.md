**Run this batch file to test the backend:**

```cmd
test_backend.bat
```

## Frontend Fix Instructions

Since your frontend is in a separate repository, find and update the API base URL:

### Option 1: Environment Variables (Recommended)

Create `.env` file in your frontend root:

```env
VITE_API_BASE_URL=http://localhost:5001
```

Then in your API client (usually `src/services/api.js`):

```javascript
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5001';
```

### Option 2: Direct Configuration

Find your API configuration file (usually `src/config/api.js` or `src/services/api.js`):

```javascript
// Change from:
export const API_BASE_URL = 'http://localhost:3001';

// To:
export const API_BASE_URL = 'http://localhost:5001';
```

### Option 3: Axios/Vite Proxy (if using Vite)

In `vite.config.js`:

```javascript
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5001',
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
```

### Option 4: For Production (Render)

```javascript
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://soc-platform-ekjv.onrender.com'
  : 'http://localhost:5001';
```

## Current Issue Summary

- ✅ Backend running correctly on port 5001
- ✅ Login endpoint works with default users
- ❌ Frontend configured to call port 3001 instead of 5001

**Fix the frontend API URL and the login will work!**