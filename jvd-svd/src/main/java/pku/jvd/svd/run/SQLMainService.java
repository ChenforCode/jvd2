package pku.jvd.svd.run;

import cn.chenforcode.common.ClassInfoCollector;
import cn.chenforcode.common.CommonArgs;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.stereotype.Component;
import pku.jvd.analysis.taint.config.SootConfig;
import pku.jvd.analysis.taint.core.TaintWrapper4;
import pku.jvd.analysis.taint.search.ChainDiscovery;
import pku.jvd.analysis.taint.search.GadgetChain;
import soot.PackManager;
import soot.SootMethod;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Component
public class SQLMainService {
    private static final Log log = LogFactory.get(SQLMainService.class);
    private static List<GadgetChain> res;

    public void runSQLAnalysis(CommonArgs args) {
        if (args.getProcessPath() == null || args.getProcessPath().equals("")) {
            log.error("processPath为空");
            return;
        }
        //对参数进行判断处理
        if (args.getVuln() == null || args.getVuln().equals("")) {
            log.error("vuln为空");
            return;
        } else {
            log.info("Init soot: {},{}", args.getProcessPath(), args.getVuln());
            SootConfig.initSootConfiguration(args.getProcessPath(),
                    args.getVuln(), args.getAlias());
        }
        if (args.getMainClass() != null && !args.getMainClass().equals("")) {
            log.info("Set soot main class: {}", args.getMainClass());
            SootConfig.setMainClass(args.getMainClass());
        }
        if (args.getEntryPoints() != null && args.getEntryPoints().size() != 0) {
            log.info("Set soot entry points: {}", args.getEntryPoints());
            List<SootMethod> entryPoints = SootConfig.getSootMethodsBySigs(args.getEntryPoints());
            SootConfig.setEntryPoints(entryPoints);
        }
        if ((args.getEntryPoints() == null || args.getEntryPoints().size() == 0) &&
                (args.getMainClass() == null) || args.getMainClass() == "") {
            //如果什么都没提供，会自动搜索类里边可能存在的入口点
            log.info("There is no mainClass and entryPoints, scan entryPoints automatically");
            ClassInfoCollector collector = new ClassInfoCollector();
            List<SootMethod> sqlTestEntryPoints = collector.getSQLTestEntryPoints(args.getProcessPath());
            List<SootMethod> webEntryPoints = collector.getWebEntryPoints(args.getProcessPath());
            sqlTestEntryPoints.addAll(webEntryPoints);
            if (sqlTestEntryPoints != null && sqlTestEntryPoints.size() != 0) {
                SootConfig.setEntryPoints(sqlTestEntryPoints);
            }
        }
        runAnalysis();
        save();
    }


    //正式分析
    public void runAnalysis() {
        //进行分析
        PackManager.v().runPacks();

        log.info("Analysis complete, begin chain search...");
        //进行搜索
        ChainDiscovery discovery = new ChainDiscovery(TaintWrapper4.taintMap,
                TaintWrapper4.sourceMap);
        discovery.discovery();
        res = discovery.chains;
        log.info("Chain search complete, chain size={}", res.size());
    }

    //保存工作
    public static void save() {
        //日志信息
        log.info("Search complete, begin chain save...");
        String path = "Search-Result-SQL/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = path + "Search-result-" + System.currentTimeMillis() + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append("Search result summary:\n");
        writer.append("Fount " + res.size() + " chains, details as follows:\n");
        for (GadgetChain chain : res) {
            writer.append(chain.toString() + " \n");
        }
        log.info("Found {} chains, search result rewrite to {}", res.size(), curFileName);
    }

    public static void main(String[] args) {
        SQLMainService sqlMainService = new SQLMainService();
        CommonArgs commonArgs = new CommonArgs();
        commonArgs.setProcessPath("jvd-taint-analysis/testJarFiles/juliet-xss-1.2.0.jar");
//        commonArgs.setEntryPoints(Collections.singletonList("<testcases.CWE89_SQL_Injection.s02.CWE89_SQL_Injection__File_prepareStatement_09: void bad()>"));
        commonArgs.setVuln("sql");
//        commonArgs.setMainClass("testcases.CWE89_SQL_Injection.s02.CWE89_SQL_Injection__Environment_execute_01");
        sqlMainService.runSQLAnalysis(commonArgs);
    }
}
