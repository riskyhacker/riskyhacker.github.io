---
title: Hacker Battle Drills 
description: Moves every hacker should know 
date: 2020-12-05
tags:
  - Hacking 
layout: layouts/post.njk
---

> A rolling list of moves every hacker should know.

### Resolve a hostname
``` shell/
dig +short $TARGET
```

### Verify a host is up 

``` shell/
ping $TARGET
```

### Probe a service 
``` shell/
echo '' | nc -vv $TARGET $PORT
```

