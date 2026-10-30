# The build output is plain static files, so it runs on the build machine's own architecture (fast, no emulation)
# and only the nginx stage below is made for each target platform.
FROM --platform=$BUILDPLATFORM node:26-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
