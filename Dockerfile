FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

ENV PORT=3001
ENV ADMIN_SECRET=savokadm8

EXPOSE 3001

CMD ["node", "server.js"]
