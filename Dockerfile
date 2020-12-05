FROM node:15

WORKDIR /blog

COPY package.json /blog/package.json
RUN npm install

ENTRYPOINT [ "/usr/local/bin/npm", "run", "start" ]
