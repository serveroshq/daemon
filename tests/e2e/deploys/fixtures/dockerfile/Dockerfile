# Three stages: the deploy builds "web" with --target. The last stage,
# which a plain build would make, exits straight away.
FROM busybox:1.36 AS base
RUN mkdir -p /www

FROM base AS web
ARG GREETING=nobody
RUN echo "greeting is $GREETING" && echo "<h1>$GREETING</h1>" > /www/index.html
EXPOSE 8080
CMD ["httpd", "-f", "-p", "8080", "-h", "/www"]

FROM base AS other
CMD ["false"]
