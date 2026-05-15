FROM node:20-alpine

WORKDIR /app

# Bağımlılıkları kopyala ve yükle
COPY package.json .
RUN npm install --omit=dev

# Kaynak kodunu kopyala
COPY . .

# Statik klasör ve data klasörü oluştur
RUN mkdir -p static data

EXPOSE 3000

CMD ["node", "server.js"]
