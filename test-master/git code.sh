#!/bin/bash

 git add .
 git commit -m "first"
 git remote rm origin
 git remote add origin git@github.com:LeonLinuxNerd/test.git
 git pull origin master
 git push -u origin master
