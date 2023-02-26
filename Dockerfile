FROM node:lts
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --production --silent && mv node_modules ../
RUN mkdir /usr/src/app/logs
COPY . .
USER node
CMD ["npm", "start"]