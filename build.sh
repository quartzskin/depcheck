#!/bin/sh
# usage: ./build.sh [test]
set -e
rm -rf out
mkdir -p out/classes
javac -Xlint:all -d out/classes src/depcheck/*.java
jar --create --file depcheck.jar --main-class depcheck.Main -C out/classes .
echo "built depcheck.jar"
if [ "$1" = "test" ]; then
  mkdir -p out/test-classes
  javac -Xlint:all -cp out/classes -d out/test-classes test/depcheck/*.java
  java -Djava.awt.headless=true -cp out/classes:out/test-classes depcheck.TestRunner
  java -Djava.awt.headless=true -jar depcheck.jar gui --snapshot out/smoke.png
  test -s out/smoke.png
fi
