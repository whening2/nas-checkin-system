# 构建阶段：使用完整版 node（自带 Python 和编译工具）
FROM node:18 AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

# 运行阶段：使用精简版 node（体积小，攻击面少）
FROM node:18-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY . .

RUN mkdir -p /data

EXPOSE 8080
CMD ["node", "server.js"]