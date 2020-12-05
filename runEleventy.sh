#!/bin/bash

# build
# docker build -t eleventy .

# debug:
docker container run --rm -it -v `pwd`:/usr/src/app -w /usr/src/app -p 8080:8080 -p 3001:3001 --entrypoint=/bin/bash eleventy

# run
# docker container run --rm -it -v `pwd`:/usr/src/app -w /usr/src/app -p 8080:8080 -p 3001:3001 eleventy
