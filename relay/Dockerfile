FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY migrations ./migrations
COPY public ./public
ENV PORT=8787 BONVOYAGE_DB=/data/bonvoyage.db
VOLUME /data
EXPOSE 8787
USER node
CMD ["node", "src/server.js"]
