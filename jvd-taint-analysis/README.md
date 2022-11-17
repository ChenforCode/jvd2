### SQL注入漏洞挖掘
#### 目录说明
* 文件目录：指交付文件目录
  * TaintAnalysis-1.0-SNAPSHOT.jar：项目主程序jar包
  * juliet-pku.jvd.deseri.test-suite-1.2.0.jar：juliet-pku.jvd.deseri.test-suite测试套件jar包
  * 测试样例名称.txt：juliet-pku.jvd.deseri.test-suite测试套件中的所有待分析主类名称
  * Search-result-sql：搜索结果存放目录
  * Test-result-sql.txt：juliet-pku.jvd.deseri.test-suite测试套件整体测试结果
* 源码目录：指交付文件目录中的jvd目录
#### 环境要求

* jdk1.8  IDEA  Maven  IDEA lombok插件

#### 源码构建
* IDEA导入jvd项目，通过maven打包子项目TaintAnalysis
* 项目jar包会输出到***jvd/TaintAnalysis/target/TaintAnalysis-1.0-SNAPSHOT.jar***
* 该jar包在文件目录已直接给出

#### 使用说明

* 输入以下命令：

  ```
  java -jar TaintAnalysis-1.0-SNAPSHOT.jar /path/toAnalaysis.jar com.package.Main
  ```

  * /path/toAnalaysis.jar 为待分析jar包路径
  * com.package.Main 为待分析jar包主类

* 样例说明：

  * 运行以下命令即可对juliet-pku.jvd.deseri.test-suite-1.2.0.jar进行分析，以CWE89_SQL_Injection__PropertiesFile_execute_01类为主入口

  ```
  java -jar TaintAnalysis-1.0-SNAPSHOT.jar juliet-pku.jvd.deseri.test-suite-1.2.0.jar cn.chenforcode.testcases.s04.CWE89_SQL_Injection__PropertiesFile_execute_01
  ```

* 直接运行文件目录中的run.sh，效果同上

  ```
  ./run.sh
  ```

* 本项目使用juliet-pku.jvd.deseri.test-suite测试套件进行测试，所有的测试文件名称在 文件目录/测试样例名称.txt中

* 进入到文件目录，输入以下命令：

  ```
  java -jar TaintAnalysis-1.0-SNAPSHOT.jar juliet-pku.jvd.deseri.test-suite-1.2.0.jar cn.chenforcode.testcases.s04.CWE89_SQL_Injection__PropertiesFile_execute_01
  ```

* 搜索完毕，控制台输出：
```
11:38:32.637 [main] INFO pku.jvd.analysis.taint.MainDriver - 搜索结束，共搜索到1条链，具体如下：
11:38:32.637 [main] INFO pku.jvd.analysis.taint.MainDriver - source: {<cn.chenforcode.testcases.s05.CWE89_SQL_Injection__PropertiesFile_execute_01: void bad()>:data = virtualinvoke $stack9.<java.util.Properties: java.lang.String getProperty(java.lang.String)>("data")}
{null:$stack19 = interfaceinvoke streamFileInput#14.<java.sql.Statement: boolean execute(java.lang.String)>($stack18)}->


11:38:32.648 [main] INFO pku.jvd.analysis.taint.MainDriver - 搜索结果重定向至Search-result-sql/Search-result-1637725112637.txt
```

* 搜索结果会生成在文件目录下的***Search-result-sql***目录中
* 注：juliet-pku.jvd.deseri.test-suite-1.2.0.jar 测试套件中所有的主类名称都在文件目录下的***测试样例名称.txt***中

#### 测试结果

```
对于juliet-pku.jvd.deseri.test-suite-1.2.0.jar内部
总共文件数：734
有Bad的文件数：420
测试成功数：189 
测试失败数：231 
```



