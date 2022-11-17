package pku.jvd.deseri.core;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.neo4j.driver.internal.value.PathValue;
import org.neo4j.driver.types.Node;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import pku.jvd.deseri.dal.neo4j.repository.ClassRefRepository;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@Component
public class Search {
    private static final Log log = LogFactory.get(Search.class);
    @Autowired
    private ClassRefRepository classRefRepository;
    @Autowired
    private ExecutorService executorService;
    private List<PathValue> pathValues = new CopyOnWriteArrayList<>();
    private List<PathValue> pathValuesCC = new CopyOnWriteArrayList<>();
    private List<PathValue> pathValuesXstream = new CopyOnWriteArrayList<>();
    private List<PathValue> pathValuesJackson = new CopyOnWriteArrayList<>();

    public void searchCommon() {
        log.info("Start to search chains.");
        long searchStartTime = System.nanoTime();
        List<String> source = new ArrayList<>();
        source.add("finalize");
        source.add("hashCode");
        source.add("equals");
        source.add("call");
        source.add("doCall");
        source.add("invoke");
        List<String> sourceSig = new ArrayList<>();
        sourceSig.add("<java.util.Hashtable: void readObject(java.io.ObjectInputStream)> ");
        sourceSig.add("<java.util.HashSet: void readObject(java.io.ObjectInputStream)> ");
        sourceSig.add("<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>");
        sourceSig.add("<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>");
        sourceSig.add("<javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>");
        List<String> sinkMethod = new ArrayList<>();
        List<String> sinkClass = new ArrayList<>();
        sinkMethod.add("exec");
        sinkMethod.add("invoke");
        sinkMethod.add("newInstance");
        sinkMethod.add("exit");
        sinkMethod.add("newOutputStream");
        sinkMethod.add("openStream");
        sinkMethod.add("newBufferedReader");
        sinkMethod.add("newBufferedWriter");
        sinkMethod.add("transform");
        sinkClass.add("java.lang.Runtime");
        sinkClass.add("java.lang.reflect.Method");
        sinkClass.add("java.net.URLClassLoader");
        sinkClass.add("java.lang.System");
        sinkClass.add("java.lang.Shutdown");
        sinkClass.add("java.lang.Runtime");
        sinkClass.add("java.nio.file.Files");
        sinkClass.add("java.lang.ProcessBuilder");
        sinkClass.add("java.lang.ClassLoader");
        sinkClass.add("java.net.URL");
        sinkClass.add("java.io.FileInputStream");
        int start = 6, end = 12, count = 0;
        //search source
        for (int i = start; i <= end; i++) {
            pathValues.addAll(classRefRepository.searchSource("readObject", sinkMethod, sinkClass, i));
            count++;
            log.info("Search progress: {}%", (int) (((double) count / ((end - start + 1) * 3)) * 100));
        }
        for (int i = start; i <= end; i++) {
            pathValues.addAll(classRefRepository.searchSourceInSig(sourceSig, sinkMethod, sinkClass, i));
            count++;
            log.info("Search progress: {}%", (int) (((double) count / ((end - start + 1) * 3)) * 100));
        }
        //search sourceList
        for (int i = start; i <= end; i++) {
            pathValues.addAll(classRefRepository.searchSourceList(source, sinkMethod, sinkClass, i));
            count++;
            log.info("Search progress: {}%", (int) (((double) count / (((end - start + 1)) * 3)) * 100));
        }
        log.info("Search chains cost {} seconds"
                , TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - searchStartTime));
        log.info("Start to save chains.");
        long saveStartTime = System.nanoTime();
        String path = "Search-Result-Deseri/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd_hh_mm_ss");
        String curFileName = path + "Search-result-" + format.format(new Date()) + ".txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append("搜索结果总结:\n");
        writer.append("共搜索到 " + pathValues.size() + " 条调用链,具体结果如下:\n");
        for (PathValue chain : pathValues) {
            save(writer, chain);
        }
        log.info("Save chains cost {} seconds"
                , TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - saveStartTime));
    }

    public void searchCVE() {
        log.info("Search cc");
        Future<?> cc = executorService.submit(() -> {
            searchCC();
        });
        log.info("Search xstream");
        Future<?> xstream = executorService.submit(() -> {
            searchXstream();
        });
        log.info("Search jackson");
        Future<?> jackson = executorService.submit(() -> {
            searchJackson();
        });
        try {
            cc.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.info("Search error!");
        } finally {
            try {
                xstream.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.info("Xstream search error!");
            } finally {
                try {
                    jackson.get(10, TimeUnit.SECONDS);
                } catch (Exception e) {
                    log.info("Jackson search error!");
                }
            }
        }
    }

    public void searchCC() {
        List<PathValue> cc1 = classRefRepository.cc1();
        List<PathValue> cc2 = classRefRepository.cc2();
        List<PathValue> cc4 = classRefRepository.cc4();
        List<PathValue> cc5 = classRefRepository.cc5();
        List<PathValue> cc6 = classRefRepository.cc6();
        List<PathValue> cc7 = classRefRepository.cc7();
        List<PathValue> cc9 = classRefRepository.cc9();
        if (cc1 != null && !cc1.isEmpty()) {
            pathValuesCC.addAll(cc1);
        }
        if (cc2 != null && !cc2.isEmpty()) {
            pathValuesCC.addAll(cc2);
        }
        if (cc4 != null && !cc4.isEmpty()) {
            pathValuesCC.addAll(cc4);
        }
        if (cc5 != null && !cc5.isEmpty()) {
            pathValuesCC.addAll(cc5);
        }
        if (cc6 != null && !cc6.isEmpty()) {
            pathValuesCC.addAll(cc6);
        }
        if (cc7 != null && !cc7.isEmpty()) {
            pathValuesCC.addAll(cc7);
        }
        if (cc9 != null && !cc9.isEmpty()) {
            pathValuesCC.addAll(cc9);
        }
        String path = "Search-Result-Deseri/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd_hh_mm_ss");
        String curFileName = path + "Search-result-" + format.format(new Date()) + "-cc.txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append("搜索结果总结:\n");
        writer.append("共搜索到 " + pathValuesCC.size() + " 条cve调用链,具体结果如下:\n");
        for (PathValue pathValue : pathValuesCC) {
            saveCVE(writer, pathValue);
        }
    }

    public void searchXstream() {
        List<PathValue> x1 = classRefRepository.cve2021_21364();
        List<PathValue> x2 = classRefRepository.cve2021_21351();
        List<PathValue> x3 = classRefRepository.cve2021_21345();
        if (x1 != null && !x1.isEmpty()) {
            pathValuesXstream.addAll(x1);
        }
        if (x2 != null && !x2.isEmpty()) {
            pathValuesXstream.addAll(x2);
        }
        if (x3 != null && !x3.isEmpty()) {
            pathValuesXstream.addAll(x3);
        }
        String path = "Search-Result-Deseri/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd_hh_mm_ss");
        String curFileName = path + "Search-result-" + format.format(new Date()) + "-xstream.txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        //输出结果保存
        writer.append("搜索结果总结:\n");
        writer.append("共搜索到 " + pathValuesXstream.size() + " 条cve调用链,具体结果如下:\n");
        for (PathValue pathValue : pathValuesXstream) {
            saveCVE(writer, pathValue);
        }
    }

    public void searchJackson() {
        //序列化的前半段
        List<PathValue> serializeFirst = classRefRepository.jacksonSerialize();
        //反序列化的前半段
        List<PathValue> deserializeFirst = classRefRepository.jacksonDeserialize();
        List<PathValue> deJK5All = classRefRepository.DeserializeAll_CVE_2020_24750();
        List<String> seSourceName = Arrays.asList("getConnection",
                "getTransactionManager",
                "getRealms",
                "getPooledConnection",
                "getPooledConnectionAndInfo",
                "registerPool");
        List<String> seSinkName = Arrays.asList("lookup", "getConnection");
        List<String> seSinkClassName = Arrays.asList("java.sql.DriverManager", "javax.naming.Context", "javax.naming.InitialContext", "org.jsecurity.jndi.JndiLocator");
        List<PathValue> seJacksonTwo1 = classRefRepository.jacksonTwo(seSourceName, seSinkName, seSinkClassName, 1);
        List<PathValue> seJacksonTwo2 = classRefRepository.jacksonTwo(seSourceName, seSinkName, seSinkClassName, 2);
        CopyOnWriteArrayList<PathValue> seJacksonTwo = new CopyOnWriteArrayList<>();
        seJacksonTwo.addAll(seJacksonTwo1);
        seJacksonTwo.addAll(seJacksonTwo2);
        List<String> deSourceName = Arrays.asList("setMetricRegistry",
                "toObjectImpl");
        List<String> deSinkName = Arrays.asList("lookup");
        List<String> deSinkClassName = Arrays.asList("javax.naming.Context", "javax.naming.InitialContext");
        List<PathValue> deJacksonTwo1 = classRefRepository.jacksonTwo(deSourceName, deSinkName, deSinkClassName, 1);
        List<PathValue> deJacksonTwo2 = classRefRepository.jacksonTwo(deSourceName, deSinkName, deSinkClassName, 2);
        CopyOnWriteArrayList<PathValue> deJacksonTwo = new CopyOnWriteArrayList<>();
        deJacksonTwo.addAll(deJacksonTwo1);
        deJacksonTwo.addAll(deJacksonTwo2);
        String path = "Search-Result-Deseri/";
        File file = new File(path);
        if (!file.exists()) {
            FileUtil.mkdir(file);
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd_hh_mm_ss");
        String curFileName = path + "Search-result-" + format.format(new Date()) + "-jackson.txt";
        File curFile = FileUtil.touch(new File(curFileName));
        FileWriter writer = new FileWriter(curFile);
        if (serializeFirst != null && seJacksonTwo != null && !serializeFirst.isEmpty() && !seJacksonTwo.isEmpty()) {
            for (PathValue first : serializeFirst) {
                for (PathValue second : seJacksonTwo) {
                    saveJacksonCVE(writer, first, second);
                }
            }
        }
        if (deserializeFirst != null && deJacksonTwo != null && !deserializeFirst.isEmpty() && !deJacksonTwo.isEmpty()) {
            for (PathValue first : deserializeFirst) {
                for (PathValue second : deJacksonTwo) {
                    saveJacksonCVE(writer, first, second);
                }
            }
        }
        if (deJK5All != null && !deJK5All.isEmpty()) {
            for (PathValue pathValue : deJK5All) {
                saveCVE(writer, pathValue);
            }
        }
    }

    //保存cc,xstream的链条
    public static void saveCVE(FileWriter writer, PathValue chain) {
        Iterable<Node> nodes = chain.asPath().nodes();
        boolean first = true;
        String name = "null", className = "null", signature = "null";
        for (Node node : nodes) {
            for (String key : node.keys()) {
                if ("NAME".equals(key)) {
                    name = node.asMap().get(key).toString();
                } else if ("CLASSNAME".equals(key)) {
                    className = node.asMap().get(key).toString();
                } else if ("SIGNATURE".equals(key)) {
                    signature = node.asMap().get(key).toString();
                }
            }
            if (first) {
                first = false;
                writer.append(String.format("%s:%s %s %n", className, name, signature));
            } else {
                writer.append(String.format("  %s:%s %s %n", className, name, signature));
            }
        }
        writer.append("\n");
    }

    //保存jackson的链条
    public static void saveJacksonCVE(FileWriter writer, PathValue firstChain, PathValue secondChain) {
        Iterable<Node> nodes = firstChain.asPath().nodes();
        boolean first = true;
        String name = "null", className = "null", signature = "null";
        //前半段
        for (Node node : nodes) {
            for (String key : node.keys()) {
                if ("NAME".equals(key)) {
                    name = node.asMap().get(key).toString();
                } else if ("CLASSNAME".equals(key)) {
                    className = node.asMap().get(key).toString();
                } else if ("SIGNATURE".equals(key)) {
                    signature = node.asMap().get(key).toString();
                }
            }
            if (first) {
                first = false;
                writer.append(String.format("%s:%s %s %n", className, name, signature));
            } else {
                writer.append(String.format("  %s:%s %s %n", className, name, signature));
            }
        }
        //后半段
        secondChain.asPath().nodes();
        Iterable<Node> secondNode = secondChain.asPath().nodes();
        Collections.reverse((List<?>) secondNode);
        for (Node node : secondNode) {
            for (String key : node.keys()) {
                if ("NAME".equals(key)) {
                    name = node.asMap().get(key).toString();
                } else if ("CLASSNAME".equals(key)) {
                    className = node.asMap().get(key).toString();
                } else if ("SIGNATURE".equals(key)) {
                    signature = node.asMap().get(key).toString();
                }
            }
            writer.append(String.format("  %s:%s %s %n", className, name, signature));
        }
        writer.append("\n");
    }

    //通用保存
    public static void save(FileWriter writer, PathValue chain) {
        Iterable<Node> nodes = chain.asPath().nodes();
        Collections.reverse((List<?>) nodes);
        boolean first = true;
        String name = "null", className = "null", signature = "null";
        for (Node node : nodes) {
            for (String key : node.keys()) {
                if ("NAME".equals(key)) {
                    name = node.asMap().get(key).toString();
                } else if ("CLASSNAME".equals(key)) {
                    className = node.asMap().get(key).toString();
                } else if ("SIGNATURE".equals(key)) {
                    signature = node.asMap().get(key).toString();
                }
            }
            if (first) {
                first = false;
                writer.append(String.format("%s:%s %s %n", className, name, signature));
            } else {
                writer.append(String.format("  %s:%s %s %n", className, name, signature));
            }
        }
        writer.append("\n");
    }
}
