FROM node:15

WORKDIR /usr/src/app

COPY package.json /usr/src/app/package.json
RUN npm install

ENTRYPOINT "npx @11ty/eleventy && npx @11ty/eleventy --serve"
