### 测试样例代码
* NPV

  ```
  java -jar jvd-run-1.0-SNAPSHOT.jar -processPath ../testJarFiles/juliet-xss-1.2.0.jar -vuln npv -mainClass testcases.CWE83_XSS_Attribute.CWE83_XSS_Attribute__Servlet_PropertiesFile_73a
  ```

* Deseri

  ```
  java -jar jvd-run-1.0-SNAPSHOT.jar -processPath ../testJarFiles/commons-collections-3.2.1.jar -vuln deseri
  ```

* SVD

  ```
  java -jar jvd-run-1.0-SNAPSHOT.jar -vuln sql -processPath sql/testPath/inter.jar -alias2
  ```

* XVD

  ```
  java -jar jvd-run-1.0-SNAPSHOT.jar -vuln xss -processPath xss/testPath/inter.jar -alias2
  ```

  