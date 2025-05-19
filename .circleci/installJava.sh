#!/bin/bash

wget https://builds.openlogic.com/downloadJDK/openlogic-openjdk/21.0.7+6/openlogic-openjdk-21.0.7+6-linux-x64.tar.gz
mkdir /usr/java
mv openlogic-openjdk-21.0.7+6-linux-x64.tar.gz /usr/java
cd /usr/java
tar -xzvf openlogic-openjdk-21.0.7+6-linux-x64.tar.gz
rm openlogic-openjdk-21.0.7+6-linux-x64.tar.gz
ln -s /usr/java/openlogic-openjdk-21.0.7+6-linux-x64/bin/java /usr/bin/java
ln -s /usr/java/openlogic-openjdk-21.0.7+6-linux-x64/bin/javac /usr/bin/javac
