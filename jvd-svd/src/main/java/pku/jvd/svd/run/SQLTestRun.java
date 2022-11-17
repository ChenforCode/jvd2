package pku.jvd.svd.run;

import cn.chenforcode.common.ClassInfoCollector;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import pku.jvd.analysis.taint.config.SootConfig;
import pku.jvd.analysis.taint.core.TaintWrapper4;
import pku.jvd.analysis.taint.search.ChainDiscovery;
import pku.jvd.analysis.taint.search.ChainNode;
import pku.jvd.analysis.taint.search.GadgetChain;
import soot.PackManager;
import soot.SootMethod;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class SQLTestRun {
    private static final Log log = LogFactory.get(SQLTestRun.class);
    private static List<GadgetChain> res;
    private static List<SootMethod> sqlEntryPoints;
    private static int classesCount;
    public static void main(String[] args) {
        long start = System.nanoTime();

        //禁止改动
        String jarPath = "testJarFiles/intra.jar";
        log.info("SQL Test Running...path:{}, vuln:{}", jarPath, "sql");
        SootConfig.initSootConfiguration(jarPath, "sql", "true2");
        ClassInfoCollector collector = new ClassInfoCollector();
        sqlEntryPoints = collector.getSQLTestEntryPoints(jarPath);
//        //测good
//        sqlEntryPoints = collector.getSQLTestGoodEntryPoints(jarPath);
        SootConfig.setEntryPoints(sqlEntryPoints);
        classesCount = collector.getClassesCount(jarPath);
        runAnalysis();
        Set<String> failResult = getAnalysisResult();
        logAnalysiResult(failResult);
        save(jarPath, failResult);
        saveFailure(jarPath, failResult);

        log.info("Total Cost {} seconds.", TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start));
    }

    public static void runAnalysis() {
        //进行分析
        PackManager.v().runPacks();

        log.info("Analysis complete,begin chain search...");
        //进行搜索
        ChainDiscovery discovery = new ChainDiscovery(TaintWrapper4.taintMap,
                TaintWrapper4.sourceMap);
        discovery.discovery();
        res = discovery.chains;
    }

    private static void logAnalysiResult(Set<String> failResult) {
        //日志信息
        log.info("搜索结束,搜索结果汇总:");
        log.info("待检测类数目:{}", classesCount);
        log.info("待检测Bad数目:{}", sqlEntryPoints.size());
        log.info("检测成功Bad数目:{}", sqlEntryPoints.size() - failResult.size());
        log.info("检测失败Bad数目:{}", failResult.size());
    }

    private static Set<String> getAnalysisResult() {
        Set<String> all = sqlEntryPoints.stream().map(e -> e.getDeclaringClass().getName()).collect(Collectors.toSet());
        HashSet<String> success = new HashSet<>();
        for (GadgetChain re : res) {
            String funcName = re.getSource().getLocationName();
            String className = funcName.split(":")[0].split("<")[1];
            success.add(className);
            for (ChainNode chainNode : re.getChain()) {
                if (chainNode.getNode().isSource()) {
                    String fakeSourceFuncName = chainNode.getNode().getLocationName();
                    String fakeSourceClassName = fakeSourceFuncName.split(":")[0].split("<")[1];
                    success.add(fakeSourceClassName);
                }
            }
        }
        //全部的减去成功的就是失败的
        all.removeAll(success);
        return all;
    }

    public static void save(String jarPath, Set<String> failResult) {
        String path = "jvd-taint-analysis/Test-result-sql/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = path + "Test-result-" + System.currentTimeMillis() + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append(jarPath + "搜索结束,搜索结果汇总:\n");
        writer.append("待检测类数目:" + classesCount + "\n");
        writer.append("待检测Bad数目:" + sqlEntryPoints.size() + "\n");
        writer.append("检测成功Bad数目:" + (sqlEntryPoints.size() - failResult.size()) + "\n");
        writer.append("检测失败Bad数目:" + failResult.size() + "\n");
        writer.append("共搜索到" + res.size() + "条链,具体如下:\n");
//        writer.append("搜索结束，搜索结果汇总：\n");
//        writer.append("待检测类数目：" + classesCount + "\n");
//        writer.append("待检测Good数目：" + sqlEntryPoints.size() + "\n");
//        writer.append("存在链Good数目：" + (sqlEntryPoints.size() - failResult.size()) + "\n");
//        writer.append("不存在链Good数目：" + failResult.size() + "\n");
//        writer.append("共搜索到" + res.size() + "条链，具体如下：\n");
        for (GadgetChain chain : res) {
            writer.append(chain.toString() + " \n");
        }
        log.info("共搜索到{}条链,搜索结果重定向至{}", res.size(), curFileName);
    }

    private static void saveFailure(String jarPath, Set<String> failResult) {
        String path = "jvd-taint-analysis/Test-result-sql-failure/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = path + "Test-result-" + System.currentTimeMillis() + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        writer.append(jarPath + "失败名单:\n");
        writer.append("共计:" + failResult.size() + "\n");
        for (String failure : failResult) {
            writer.append(failure + "\n");
        }
        log.info("失败名单重定向至:{}", curFileName);
    }
}
