package pku.jvd.run;

import cn.chenforcode.common.CommonArgs;
import cn.hutool.core.util.RuntimeUtil;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.neo4j.repository.config.EnableNeo4jRepositories;
import pku.jvd.deseri.DeseriMainService;
import pku.jvd.run.core.JVDEntry;
import pku.jvd.run.core.exception.AnalysisException;
import pku.jvd.run.core.exception.OptionException;
import pku.jvd.svd.run.SQLMainService;
import pku.jvd.xvd.run.XSSMainService;

@EntityScan({"pku.jvd.deseri.dal.caching.bean","pku.jvd.deseri.dal.neo4j.entity"})
@EnableNeo4jRepositories("pku.jvd.deseri.dal.neo4j.repository")
@ComponentScan("pku.jvd")
@SpringBootApplication(scanBasePackages = "pku.jvd")
public class JVDApplication {
    private static final Log log = LogFactory.get(JVDApplication.class);
    @Autowired
    private JVDEntry jvdEntry;

    @Autowired
    private XSSMainService xssMainService;

    @Autowired
    private SQLMainService sqlMainService;

    @Autowired
    private DeseriMainService deseriMainService;

//    @Autowired
//    private NPVMainService npvMainService;

    public static void main(String[] args) {
        SpringApplication.run(JVDApplication.class, args);
    }

    @Bean
    CommandLineRunner run() {
        return args -> {
            try {
                CommonArgs commonArgs = jvdEntry.initOptions(args);
                String vuln = commonArgs.getVuln();
                if (vuln.equals("xss")) {
                    xssMainService.runXSSAnalysis(commonArgs);
                } else if (vuln.equals("sql")) {
                    sqlMainService.runSQLAnalysis(commonArgs);
                } else if (vuln.equals("deseri")) {
                    deseriMainService.runDeseriAnalysis(commonArgs);
                } else if (vuln.equals("npv")) {
                    String[] npArgs = commonArgs.commonArgsToNPVArgs();
//                    npvMainService.runNullPointerAnalysis(npArgs);
                    String javaCmd = "java -jar";
                    String npJarPath = "./npv/jvd-npv-1.0-SNAPSHOT.jar ";
                    String npCmdArgs = "-apppath " + npArgs[1] + " -mainclass " + npArgs[3];
                    if (npArgs.length == 6 && npArgs[5] != null) {
                        npCmdArgs += " -jre " + npArgs[5];
                    }
                    String wholeCmd = javaCmd + " " + npJarPath + " " + npCmdArgs;
                    String res = RuntimeUtil.execForStr(wholeCmd);
                    log.info(res);
                } else if (vuln == null || vuln.equals("")) {
                    log.error("没有vuln参数");
                }
                System.exit(-1);
            } catch (UnrecognizedOptionException | OptionException e) {
//                log.error("There are several mistakes in arguments");
//                log.error(e.getMessage() +
//                        "\nPlease use java -jar jvd -processPath targetPath -vuln xss [-mainClass｜-entryPoints...] !" +
//                        "\n-processPath targetPath 为待检测jar包路径，所有漏洞类型必选" +
//                        "\n-vuln 指定分析漏洞类型，参数包括[xss|sql|deseri|npv]，所有漏洞类型必选" +
//                        "\n-mainClass 指定待分析jar包的主类，需要包含包名和类名组成的完整名称，[npv]漏洞类型必选" +
//                        "\n-entryPoints 指定待分析jar包的分析入口方法，需要指定该方法的完整签名，[xss|sql]漏洞类型可选" +
//                        "\n[sql|xss]漏洞类型若无-entryPoints和-mainClass参数，程序会自动分析待检测jar包中的入口点"+
//                        "\n-deseriKind [deseri]漏洞扫描类型，[deseri]漏洞类型可选" +
//                        "\n-taint [deseri]漏洞扫描是否开始污点分析，参数包括[true|false]，[deseri]漏洞类型可选" +
//                        "\n-jre [npv]漏洞指定运行环境，[npv]漏洞类型可选" +
//                        "\nExample: java -jar juliet-xss-1.2.0.jar -vuln xss -entryPoints \"<testcases.CWE80_XSS.s01.CWE80_XSS__Servlet_getQueryString_Servlet_07: void bad(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>\"");
                log.error(e.getMessage());
                System.exit(-1);
            } catch (AnalysisException e) {
                //TODO analysis exception
                System.exit(-1);
            }
        };
    }
}
