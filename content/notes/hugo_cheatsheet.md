---
title: "Hugo cheatsheet"
date: 2020-07-29T22:13:59+08:00
draft: true
categories: ['notes']
tags: ['tips']
---

# Motivation

It's been a while since I blogged. And I realised that I have almost forgotten how to use hugo and many of the things I used to do. It's such a pity that we can spend so much time learning stuff just to forget them later. I used to think my memory is pretty good but it seems to be no longer the case. So I am starting to document every little things I learn from now on so that I can have a quick reference to things that I need.

# Basic workflow

## Creating and testing new blog post
|   |   |
|---|---|
|hugo new site site_name         |  #create a new site|
|hugo new notes/postname.md      |  #create a new post in content/notes/|
|hugo                            |  #builds static website in public/|
|hugo server -D                  |  #starts a server to see how your blog looks like|

## Deploy
A simple bash script to deploy to an ssh server

```bash

#!/bin/bash

USER=$1
HOST=$2

echo "Deploying to" ${USER}@${HOST}

hugo && rsync -avz --delete public/ ${USER}@${HOST}:/var/www/hugoblog/

exit 0
```

