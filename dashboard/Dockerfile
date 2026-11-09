FROM node:20-alpine AS build

WORKDIR /dashboard
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /dashboard/dist/ /usr/share/nginx/html/
EXPOSE 8080
