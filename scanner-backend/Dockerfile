FROM clamav/clamav:stable

USER root

RUN apk add --no-cache nodejs npm

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY start.sh ./

RUN chmod +x start.sh

ENV PORT=10000

EXPOSE 10000

CMD ["/app/start.sh"]
