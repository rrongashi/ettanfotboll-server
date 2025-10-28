# Setup Instructions

## Prerequisites
- Docker Desktop installed and running

## First Time Setup

### 1. Clone the repository
```bash
git clone <repository-url>
cd ettanfotboll-server
```

### 2. Copy environment file
```bash
cp env-example-document .env
```

### 3. Start Docker containers
```bash
npm run docker:dev:up
```

### 4. Verify it's running
- API: http://localhost:3000
- API Docs: http://localhost:3000/docs
- Mongo Express: http://localhost:8081
- Maildev: http://localhost:1080

**Done!** The database will be created automatically and seeded with initial data.

## Daily Development

### Starting the application
```bash
npm run docker:dev:up
```

### Stopping the application
```bash
npm run docker:dev:down
```

### After pulling code changes
```bash
# 1. Pull changes
git pull

# 2. If package.json dependencies changed, rebuild
npm run docker:dev:rebuild

# 3. If .env changed, restart
npm run docker:dev:restart

# 4. Otherwise, code changes auto-reload
```

## Useful Commands

### View logs
```bash
npm run docker:dev:logs:api    # API logs only
npm run docker:dev:logs:db     # Database logs only
```

### Restart services
```bash
npm run docker:dev:restart     # Restart all services
npm run docker:dev:rebuild     # Rebuild and restart
```

### Database operations
```bash
npm run docker:dev:seed        # Run database seeds
npm run docker:dev:shell        # Open shell in container
```

### Stop and remove data
```bash
npm run docker:dev:down        # Stop (data persists)
docker compose -f docker-compose.document.dev.yaml down -v  # Remove data too
```

## Troubleshooting

### Port already in use
```bash
# Stop everything
npm run docker:dev:down

# Check what's using the port
lsof -i :3000

# Kill the process or change port in .env
```

### Database connection errors
```bash
# Check database logs
npm run docker:dev:logs:db

# Restart database
docker compose -f docker-compose.document.dev.yaml restart mongo
```

### Complete fresh start
```bash
npm run docker:dev:down
docker compose -f docker-compose.document.dev.yaml down -v
npm run docker:dev:up
```

## Development Workflow

### Making code changes
- Edit code in `src/` folder
- Changes automatically reload (dev mode)
- No restart needed

### Making .env changes
1. Edit `.env` file
2. Run `npm run docker:dev:restart`
3. Changes applied

### Adding new dependencies
1. Update `package.json` dependencies
2. Run `npm run docker:dev:rebuild`
3. Dependencies installed
