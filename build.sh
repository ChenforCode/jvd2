#!/bin/bash

set -e

BASE_DIR="$(cd "$( dirname "$0")" && pwd)"
RUN_ENV="${BASE_DIR}/run_env"
echo "Start Build JVD"
echo "Current Dir: ${BASE_DIR}"
# maven安装相应的依赖
mvn install:install-file -Dfile=lib/druid-1.0.jar -DgroupId=pku.jvd.npv -DartifactId=druid -Dversion=1.0 -Dpackaging=jar
mvn install:install-file -Dfile=lib/PathExpression.jar -DgroupId=de.fraunhofer.iem -DartifactId=PathExpression -Dversion=1.0.0 -Dpackaging=jar
mvn clean package

rm -rf ${RUN_ENV}

# run_env环境
mkdir ${RUN_ENV}

# npv的测试文件夹路径
mkdir -p ${RUN_ENV}/npv/testPath

# deseri的cc测试路径
mkdir -p ${RUN_ENV}/deseri/testPath
#

# sql的测试文件夹路径
mkdir -p ${RUN_ENV}/sql/testPath

# sql的测试文件夹路径
mkdir -p ${RUN_ENV}/xss/testPath

# 生成日志目录
mkdir -p ${RUN_ENV}/logs

# cp npv所需文件
cp jvd-run/target/jvd-run-1.0-SNAPSHOT.jar ${RUN_ENV}
cp -r jvd-npv/jre/jre1.6.0_45 ${RUN_ENV}/npv
cp testJarFiles/HelloWorld.jar ${RUN_ENV}/npv/testPath
cp jvd-run/target/jvd-run-1.0-SNAPSHOT.jar ${RUN_ENV}
cp jvd-npv/target/jvd-npv-1.0-SNAPSHOT.jar ${RUN_ENV}/npv

# cp deseri所需文件
cp testJarFiles/commons-collections-3.1.jar ${RUN_ENV}/deseri/testPath
rm -rf deseri/cache
cp -r deseri/* ${RUN_ENV}/deseri/
rm -rf ${RUN_ENV}/deseri/cache
mkdir ${RUN_ENV}/deseri/cache

# cp sql和xss所需文件
cp testJarFiles/inter.jar ${RUN_ENV}/sql/testPath
cp testJarFiles/inter.jar ${RUN_ENV}/xss/testPath
cd ${RUN_ENV}
echo ${RUN_ENV}
