@echo off
rem usage: build.cmd [test]
setlocal
if exist out rmdir /s /q out
mkdir out\classes || exit /b 1
javac -Xlint:all -d out\classes src\depcheck\*.java || exit /b 1
jar --create --file depcheck.jar --main-class depcheck.Main -C out\classes . || exit /b 1
echo built depcheck.jar
if /i "%1"=="test" (
  mkdir out\test-classes || exit /b 1
  javac -Xlint:all -cp out\classes -d out\test-classes test\depcheck\*.java || exit /b 1
  java -Djava.awt.headless=true -cp out\classes;out\test-classes depcheck.TestRunner || exit /b 1
  java -Djava.awt.headless=true -jar depcheck.jar gui --snapshot out\smoke.png || exit /b 1
  if not exist out\smoke.png (exit /b 1)
)
