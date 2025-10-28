FROM node:22.19.0-alpine

RUN apk add --no-cache bash
RUN npm i -g @nestjs/cli typescript ts-node

COPY package*.json /tmp/app/
RUN cd /tmp/app && npm install

COPY . /usr/src/app
RUN cp -a /tmp/app/node_modules /usr/src/app
COPY ./wait-for-it.sh /opt/wait-for-it.sh
RUN chmod +x /opt/wait-for-it.sh
COPY ./startup.document.dev.watch.sh /opt/startup.document.dev.watch.sh
RUN chmod +x /opt/startup.document.dev.watch.sh
RUN sed -i 's/\r//g' /opt/wait-for-it.sh
RUN sed -i 's/\r//g' /opt/startup.document.dev.watch.sh

WORKDIR /usr/src/app

CMD ["/opt/startup.document.dev.watch.sh"]

