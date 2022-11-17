package pku.jvd.analysis.taint.run;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.apache.commons.cli.*;
import pku.jvd.analysis.taint.config.SootConfig;
import pku.jvd.analysis.taint.core.TaintWrapper4;
import pku.jvd.analysis.taint.core.pointerAnalysisTransformer;
import pku.jvd.analysis.taint.search.ChainDiscovery;
import pku.jvd.analysis.taint.search.GadgetChain;
import soot.PackManager;
import soot.SootMethod;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class MainRun {
    private static final Log log = LogFactory.get(MainRun.class);
    private static List<GadgetChain> res;
    private static String processPath = "";
    private static String mainClass = "";
    private static String entryPoints = "";
    private static String ifAliasAnalysis = "false";

    public static void main(String[] args) throws ParseException {
        //处理参数问题
        initOptions(args);
        //处理soot基本设置
        log.info("设置检测路径:{}", processPath);
        String vuln = "all";
        SootConfig.initSootConfiguration(processPath, vuln, ifAliasAnalysis);
        //设置主类
        if (mainClass != null && !mainClass.equals("")) {
            log.info("设置主类:{}", mainClass);
            SootConfig.setMainClass(mainClass);
        }
        //设置入口点
        if (entryPoints != null && !entryPoints.equals("")) {
            log.info("设置入口点:{}", entryPoints);
            if (entryPoints.contains(",")) {
                List<SootMethod> methods = SootConfig.getSootMethodsBySigs(Arrays.asList(entryPoints.split(",")));
                SootConfig.setEntryPoints(methods);
            } else {
                SootMethod method = SootConfig.getSootMethodBySig(entryPoints);
                SootConfig.setEntryPoints(Collections.singletonList(method));
            }
        }
//        SootConfig.setEntryPoints(new ClassInfoCollector().getXSSTestEntryPoints(processPath));
        runAnalysis();
        save();
    }

    //处理相关命令行参数
    private static void initOptions(String[] args) throws ParseException {
        CommandLineParser commandLineParser = new DefaultParser();
        Options options = new Options();
        options.addOption("processPath", true, "待分析文件理解");
        options.addOption("mainClass", true, "标志");
        options.addOption("entryPoints", true, "入口点");
        options.addOption("alias1",false,"别名分析开关");
        options.addOption("alias2",false,"别名分析开关");
        CommandLine commandLine = commandLineParser.parse(options, args);
        if (commandLine.hasOption("processPath")) {
            processPath = commandLine.getOptionValue("processPath");
        } else {
            log.info("请输入processPath");
            System.exit(-1);
        }
        if (commandLine.hasOption("mainClass")) {
            mainClass = commandLine.getOptionValue("mainClass");
        }
        if (commandLine.hasOption("entryPoints")) {
            entryPoints = commandLine.getOptionValue("entryPoints");
        }
        if (commandLine.hasOption("alias1")) {
            ifAliasAnalysis = "true1";
        }
        if (commandLine.hasOption("alias2")) {
            ifAliasAnalysis = "true2";
        }
    }

    //正式分析
    public static void runAnalysis() {
        //进行分析
        PackManager.v().runPacks();


        log.info("Analysis complete,begin chain search...");
        //进行搜索
        ChainDiscovery discovery = new ChainDiscovery(TaintWrapper4.taintMap,
                TaintWrapper4.sourceMap);
        discovery.discovery();
        res = discovery.chains;
        //log.info("Alias search complete: " + pointerAnalysisTransformer.aliasSetRes);
        log.info("Chain search complete,chain size={}", res.size());
        log.info("Chain details:");
        for (GadgetChain chain : res) {
            log.info(chain.toString());
        }
    }

    //保存工作
    public static void save() {
        //日志信息
        log.info("Search complete,begin chain save...");
        String path = "Search-Result/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = path + "Search-result-" + System.currentTimeMillis() + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append("搜索结束,搜索结果汇总:\n");
        writer.append("共搜索到" + res.size() + "条链,具体如下:\n");
        for (GadgetChain chain : res) {
            writer.append(chain.toString() + " \n");
        }
        log.info("共搜索到{}条链,搜索结果重定向至{}", res.size(), curFileName);
    }
}
