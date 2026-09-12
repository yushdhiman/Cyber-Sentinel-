FROM node:20-alpine

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install reproducible production dependencies
RUN npm ci --omit=dev

# Copy source code with appropriate ownership
COPY --chown=node:node src/ ./src/

# Run container as unprivileged user
USER node

# Environment variables
ENV PORT=5000
ENV NODE_ENV=production

EXPOSE 5000

CMD ["node", "src/server.js"]
