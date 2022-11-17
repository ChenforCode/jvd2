package pku.jvd.xvd.run;

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

public class XSSTestRun {
    private static final Log log = LogFactory.get(XSSTestRun.class);
    private static List<GadgetChain> res;
    private static List<SootMethod> xssEntryPoints;
    private static int classesCount;
    public static void main(String[] args) {
        long start = System.nanoTime();
        //禁止改动
        String jarPath = "testJarFiles/CWE83_XSS_Attribute_Inter-1.2.0.jar";
        log.info("XSS Test Running...path:{},vuln{}", jarPath, "xss");
        SootConfig.initSootConfiguration(jarPath, "xss", "false");
        ClassInfoCollector collector = new ClassInfoCollector();
        xssEntryPoints = collector.getXSSTestEntryPoints(jarPath);
//        xssEntryPoints = collector.getXSSGoodTestEntryPoints(jarPath);
        SootConfig.setEntryPoints(xssEntryPoints);
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

    private static Set<String> getAnalysisResult() {
        Set<String> all = xssEntryPoints.stream().map(e -> e.getDeclaringClass().getName()).collect(Collectors.toSet());
        HashSet<String> success = new HashSet<>();
        for (GadgetChain re : res) {
            String funcName = re.getSource().getLocationName();
            //加入真正的source
            String className = funcName.split(":")[0].split("<")[1];
            success.add(className);
            //加入节点里假的source，此处解决的问题是:
            /**
             * 我们认为all是所有的bad方法，成功是，source在bad里，并且从该source走出了一条链
             * 失败是，bad里边没有source，或者有source但是没有链
             *
             * 所以我们可以通过计算链的source所在的方法，所在的类进行比对匹配，得到成功的，也就得到了失败的
             *
             * 但是现在有这样的情况 realSource in badSource   badSource in bad
             * 因此真正的source是从badSource出发的，因此我们认为bad没有source，也就是一个失败的
             * 所以在此做的一个步骤就是将realSource所在类和badSource所在类都加入到success里，
             *
             * 但是all - success = fail 这样导致的success增大会不会影响fail呢，答案是不会的，
             * 因为这里都是集合运算，all.remove(success)，增多的那几个realSource所在类在success里
             * 根本就没有，所以remove的时候也就不会影响。
             **/
            //加入假source
            List<ChainNode> chain = re.getChain();
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

    private static void logAnalysiResult(Set<String> failResult) {
        //日志信息
        log.info("搜索结束，搜索结果汇总:");
        log.info("待检测类数目:{}", classesCount);
        log.info("待检测Bad数目:{}", xssEntryPoints.size());
        log.info("检测成功Bad数目:{}", xssEntryPoints.size() - failResult.size());
        log.info("检测失败Bad数目:{}", failResult.size());
    }

    public static void save(String jarPath, Set<String> failResult) {
        String path = "jvd-taint-analysis/Test-result-xss/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = path + "Test-result-" + System.currentTimeMillis() + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append(jarPath + "搜索结束，搜索结果汇总:\n");
        writer.append("待检测类数目:" + classesCount + "\n");
        writer.append("待检测Bad数目:" + xssEntryPoints.size() + "\n");
        writer.append("检测成功Bad数目:" + (xssEntryPoints.size() - failResult.size()) + "\n");
        writer.append("检测失败Bad数目:" + failResult.size() + "\n");
//        writer.append("待检测Good数目：" + xssEntryPoints.size() + "\n");
//        writer.append("存在链Good数目：" + (xssEntryPoints.size() - failResult.size()) + "\n");
//        writer.append("不存在链Good数目：" + failResult.size() + "\n");
        writer.append("共搜索到" + res.size() + "条链，具体如下:\n");
        for (GadgetChain chain : res) {
            writer.append(chain.toString() + " \n");
        }
        log.info("共搜索到{}条链，搜索结果重定向至{}", res.size(), curFileName);
    }


    private static void saveFailure(String jarPath, Set<String> failResult) {
        String path = "jvd-taint-analysis/Test-result-xss-failure/";
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
