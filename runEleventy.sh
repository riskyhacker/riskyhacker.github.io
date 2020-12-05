#!/bin/bash

# build
# docker build -t 11ty .

# debug:
# docker container run --rm -it -v `pwd`:/blog -w /blog -p 8080:8080 -p 3001:3001 --entrypoint=/bin/bash 11ty 

# run
docker container run --rm -it -v `pwd`:/blog -w /blog -p 8080:8080 -p 3001:3001 11ty 
