FROM nginx:1.25-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom config
COPY nginx.conf /etc/nginx/conf.d/waf.conf

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# Create log directory
RUN mkdir -p /var/log/nginx

EXPOSE 80 443
