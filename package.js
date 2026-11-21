{
  "name": "private-intelligence-platform",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "db:local": "wrangler d1 execute intelligence-db --local --file=./schema.sql",
    "db:remote": "wrangler d1 execute intelligence-db --remote --file=./schema.sql"
  },
  "dependencies": {
    "jose": "^5.9.6",
    "pdf-lib": "^1.17.1"
  },
  "devDependencies": {
    "wrangler": "^4.20.0"
  }
}
