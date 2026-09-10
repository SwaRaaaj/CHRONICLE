# Chronicle Autonomous Action Control Plane (AACT)
# Production Container Image
FROM node:22-alpine

WORKDIR /app

# Copy dependency manifests and source trees
COPY package.json tsconfig.json ./
COPY packages ./packages
COPY apps ./apps

# Cloud provider port injection & unprivileged execution
ENV PORT=3000
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV CHRONICLE_START_SERVER=true

EXPOSE 3000

# Start Chronicle Control Plane HTTP & Cybernetic HUD Web Server
CMD ["node", "--preserve-symlinks", "--preserve-symlinks-main", "--experimental-strip-types", "apps/control-plane/src/index.ts"]
