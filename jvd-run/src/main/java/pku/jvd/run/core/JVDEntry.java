package pku.jvd.run.core;

import cn.chenforcode.common.CommonArgs;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.apache.commons.cli.*;
import org.springframework.stereotype.Component;
import pku.jvd.run.core.exception.OptionException;

import javax.smartcardio.CommandAPDU;
import java.util.Arrays;
import java.util.Collections;

@Component
public class JVDEntry {
    private static final Log log = LogFactory.get(JVDEntry.class);

    public CommonArgs initOptions(String[] args) throws ParseException, Exception {
        CommonArgs commonArgs = new CommonArgs();
        //处理相关命令行参数
        CommandLineParser commandLineParser = new DefaultParser();
        Options options = new Options();
        options.addOption("processPath", true, "待分析文件理解");
        options.addOption("vuln", true, "分析漏洞类型");
        options.addOption("mainClass", true, "标志");
        options.addOption("entryPoints", true, "入口点");
        options.addOption("deseriKind", true, "反序列化漏洞类型");
        options.addOption("taint", true, "是否启用污点分析");
        Option option = new Option("jre", true, "NPV的jre环境参数");
        option.setRequired(false);
        options.addOption(option);

        options.addOption("processJDK", false, "是否处理jdk + 三方包");
        options.addOption("excludeJDK", false, "是否移除jdk,只处理三方包");
        options.addOption("search", false, "是否只进行搜索");

        //别名分析
        options.addOption("alias1", false, "是否开启全量别名分析");
        options.addOption("alias2", false, "是否开启轻量别名分析");

        CommandLine commandLine = commandLineParser.parse(options, args);
        if (commandLine.hasOption("processPath")) {
            String processPath = commandLine.getOptionValue("processPath");
            commonArgs.setProcessPath(processPath);
        } else {
            throw new OptionException("There is no processPath in arguments");
        }
        if (commandLine.hasOption("vuln")) {
            String vuln = commandLine.getOptionValue("vuln");
            commonArgs.setVuln(vuln);
        } else {
            throw new OptionException("There is no vuln in arguments");
        }
        if (commandLine.hasOption("mainClass")) {
            String mainClass = commandLine.getOptionValue("mainClass");
            commonArgs.setMainClass(mainClass);
        }
        if (commonArgs.getVuln().equals("npv") && !commandLine.hasOption("mainClass")) {
            throw new OptionException("There is no mainClass in arguments in vuln npv");
        }
        if (commandLine.hasOption("entryPoints")) {
            String entryPoints = commandLine.getOptionValue("entryPoints");
            if (entryPoints.contains("&")) {
                commonArgs.setEntryPoints(Arrays.asList(entryPoints.split("&")));
            } else {
                commonArgs.setEntryPoints(Collections.singletonList(entryPoints));
            }
        }

        //deseri参数处理
        if (commandLine.hasOption("deseriKind")) {
            commonArgs.setDeseriKind(commandLine.getOptionValue("deseriKind"));
        }
        if (commandLine.hasOption("taint")) {
            commonArgs.setTaint(commandLine.getOptionValue("taint"));
        }
        if (commandLine.hasOption("processJDK")) {
            commonArgs.setProcessJDK("true");
        }
        if (commandLine.hasOption("excludeJDK")) {
            commonArgs.setExcludeJDK("true");
        }
        if (commandLine.hasOption("search")) {
            commonArgs.setSearch("true");
        }
        if (commandLine.hasOption("alias1") && commandLine.hasOption("alias2")) {
            throw new OptionException("alias参数异常");
        }
        if (commandLine.hasOption("alias1")) {
            commonArgs.setAlias("true1");
        }
        if (commandLine.hasOption("alias2")) {
            commonArgs.setAlias("true2");
        }


        //np参数处理
        if (commandLine.hasOption("jre")) {
            commonArgs.setJre(commandLine.getOptionValue("jre"));
        }
        return commonArgs;
    }
}
