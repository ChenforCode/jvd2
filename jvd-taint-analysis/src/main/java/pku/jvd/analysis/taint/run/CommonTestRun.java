package pku.jvd.analysis.taint.run;

import cn.hutool.core.io.FileUtil;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import pku.jvd.analysis.taint.config.SootConfig;
import pku.jvd.analysis.taint.core.TaintWrapper4;
import pku.jvd.analysis.taint.core.pointerAnalysisTransformer;
import pku.jvd.analysis.taint.search.ChainDiscovery;
import pku.jvd.analysis.taint.search.GadgetChain;
import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.Value;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @description 普通测试工作，可以自定义测试路径，主类，签名等，直接修改对应字符即可
 */
public class CommonTestRun {
    private static final Log log = LogFactory.get(CommonTestRun.class);

    public static void main(String[] args) throws IOException {
        //此处填成待测试文件路径，必填
        String jarPath = "jvd-taint-analysis/testClassFiles/singleTest";
        //此处填写主类名称，如果有
        String mainClass = "";
        //此处填写entry points（方法签名），如果有
        String[] methodSigs = new String[]{"<testcases.CWE80_XSS.s01.CWE80_XSS__CWE182_Servlet_connect_tcp_68a: void bad(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>"};
        String vuln = "xss";
        log.info("Common Test Running...{}", jarPath);

        //设置classPath
        SootConfig.initSootConfiguration(jarPath, vuln, "true2");

        //设置entry points
        if (methodSigs != null && methodSigs.length != 0) {
            List<SootMethod> entryPoints = Arrays.stream(methodSigs).map(e -> Scene.v().getMethod(e)).collect(Collectors.toList());
            SootConfig.setEntryPoints(entryPoints);
        }
        //设置main class
        if (mainClass != null && !mainClass.equals("")) {
            SootConfig.setMainClass(mainClass);
        }
        runAnalysis();
        savePointer(pointerAnalysisTransformer.aliasSetRes);
    }


    public static void runAnalysis() {
        //进行分析
        PackManager.v().runPacks();

        log.info("Analysis complete,begin chain search...");
        //进行搜索
        ChainDiscovery discovery = new ChainDiscovery(TaintWrapper4.taintMap,
                TaintWrapper4.sourceMap);
        discovery.discovery();
        List<GadgetChain> res = discovery.chains;
        log.info("Chain search complete,chain size={}", res.size());
        log.info("Chain details:");
        for (GadgetChain chain : res) {
            log.info(chain.toString());
        }
    }

    public static void savePointer(Set<Set<Value>> ptrRes) throws IOException {
        String path = "jvd-taint-analysis/Test-result-pointer/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = path + "Test-result-" + System.currentTimeMillis() + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        for(Set<Value> s:ptrRes){
            for(Value v : s){
                writer.append(String.valueOf(v));
                writer.append("  ");
            }
            writer.append("\n");
        }
    }
}