package pku.jvd.analysis.taint.run;

import cn.chenforcode.common.ClassInfoCollector;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import pku.jvd.analysis.taint.config.SootConfig;
import soot.SootMethod;

import java.io.File;
import java.util.List;

public class GenerateAllSigs {
    private static final Log log = LogFactory.get(GenerateAllSigs.class);
    private static final String jarPath = "jvd-taint-analysis/testJarFiles/juliet-xss-sql-1.2.0.jar";

    public static void main(String[] args) {
        //禁止改动
        SootConfig.initSootConfiguration(jarPath);
        generateSql();
        generateXss();
    }

    private static void generateXss() {
        log.info("生成xss的所有bad签名...");
        ClassInfoCollector collector = new ClassInfoCollector();
        List<SootMethod> xssSigs = collector.getXSSTestEntryPoints(jarPath);

        String filePath = "jvd-taint-analysis/testSigs/";
        File file = new File(filePath);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = filePath + "Xss-sigs.txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        writer.write("");
        for (SootMethod xssSig : xssSigs) {
            writer.append(xssSig.getSignature() + "\n");
        }
        log.info("xss签名生成完成,输出重定向至:{},共计:{}", curFileName, xssSigs.size());
    }

    private static void generateSql() {
        log.info("生成sql的所有bad签名...");
        ClassInfoCollector collector = new ClassInfoCollector();
        List<SootMethod> sqlSigs = collector.getSQLTestEntryPoints(jarPath);

        String filePath = "jvd-taint-analysis/testSigs/";
        File file = new File(filePath);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        String curFileName = filePath + "Sql-sigs.txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        writer.write("");
        for (SootMethod sqlSig : sqlSigs) {
            writer.append(sqlSig.getSignature() + "\n");
        }
        log.info("sql签名生成完成,输出重定向至:{},共计:{}", curFileName, sqlSigs.size());
    }
}
