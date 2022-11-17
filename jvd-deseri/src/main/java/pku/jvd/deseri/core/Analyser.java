package pku.jvd.deseri.core;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import pku.jvd.deseri.config.GlobalConfiguration;
import pku.jvd.deseri.config.SootConfiguration;
import pku.jvd.deseri.core.container.DataContainer;
import pku.jvd.deseri.core.container.RulesContainer;
import pku.jvd.deseri.core.scanner.CallGraphScanner;
import pku.jvd.deseri.core.scanner.ClassInfoScanner;
import pku.jvd.deseri.core.scanner.FullCallGraphScanner;
import pku.jvd.deseri.util.ArgumentEnum;
import pku.jvd.deseri.util.FileUtils;
import soot.CompilationDeathException;
import soot.G;
import soot.Main;
import soot.Scene;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static soot.SootClass.HIERARCHY;

@Component
public class Analyser {
    private static final Log log = LogFactory.get(Analyser.class);
    @Autowired
    private DataContainer dataContainer;
    @Autowired
    private ClassInfoScanner classInfoScanner;
    @Autowired
    private CallGraphScanner callGraphScanner;
    @Autowired
    private FullCallGraphScanner fullCallGraphScanner;
    @Autowired
    private RulesContainer rulesContainer;

    public void run(Properties props) throws IOException {

        if ("true".equals(props.getProperty(ArgumentEnum.BUILD_ENABLE.toString(), "false"))) {
            //获取本机jdk依赖
            Map<String, String> dependencies = getJdkDependencies(
                    props.getProperty(ArgumentEnum.WITH_ALL_JDK.toString(), "false"));
            log.info("Get {} JDK dependencies", dependencies.size());

            //排除本机依赖，cp为空，不排除，cp为上述获取的依赖
            Map<String, String> cps = "true".equals(props.getProperty(ArgumentEnum.EXCLUDE_JDK.toString(), "false")) ?
                    new HashMap<>() : new HashMap<>(dependencies);
            Map<String, String> targets = new HashMap<>();
            // 收集目标
            String target = props.getProperty(ArgumentEnum.TARGET.toString());
            boolean checkFatJar = "true".equals(props.getProperty(ArgumentEnum.CHECK_FAT_JAR.toString(), "false"));
            Map<String, String> files = FileUtils.getTargetDirectoryJarFiles(target, checkFatJar);
            cps.putAll(files);
            targets.putAll(files);
            if ("true".equals(props.getProperty(ArgumentEnum.IS_JDK_PROCESS.toString(), "false"))) {
                targets.putAll(dependencies);
            }
            // 添加必要的依赖，防止信息缺失，比如servlet依赖
            if (FileUtils.fileExists(GlobalConfiguration.LIBS_PATH)) {
                Map<String, String> mustFiles = FileUtils.getTargetDirectoryJarFiles(GlobalConfiguration.LIBS_PATH, false);
                for (Map.Entry<String, String> entry : mustFiles.entrySet()) {
                    cps.putIfAbsent(entry.getKey(), entry.getValue());
                }
            }
            //target是具体分析的， cps是soot classpath
            runSootAnalysis(targets, new ArrayList<>(cps.values()));
        }

        if ("true".equals(props.getProperty(ArgumentEnum.LOAD_ENABLE.toString(), "false"))) {
            G.reset();
            save();
        }
    }

    public void runSootAnalysis(Map<String, String> targets, List<String> classpaths) {
        try {
            log.info("Start to analysis.");
            long start = System.nanoTime();
            SootConfiguration.initSootOption();
            addBasicClasses();
            // set class paths
            Scene.v().setSootClassPath(String.join(File.pathSeparator, new HashSet<>(classpaths)));
            // get target filepath
            List<String> realTargets = getTargets(targets);
            if (realTargets.isEmpty()) {
                log.info("Nothing to analysis!");
                return;
            }
            Main.v().autoSetOptions();
            log.info("Target {}, Dependencies {}", realTargets.size(), classpaths.size());
            // 类信息抽取
            classInfoScanner.run(realTargets);
            // 函数调用分析
            if (GlobalConfiguration.IS_FULL_CALL_GRAPH_CONSTRUCT) {
                fullCallGraphScanner.run();
            } else {
                callGraphScanner.run();
            }
            rulesContainer.saveStatus();
            log.info("Analysis Cost {} seconds"
                    , TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start));
        } catch (CompilationDeathException e) {
            if (e.getStatus() != CompilationDeathException.COMPILATION_SUCCEEDED) {
                throw e;
            }
        }
    }

    public List<String> getTargets(Map<String, String> targets) {
        Set<String> stuff = new HashSet<>();
        List<String> newIgnore = new ArrayList<>();
        targets.forEach((filename, filepath) -> {
            if (!rulesContainer.isIgnore(filename)) {
                stuff.add(filepath);
                newIgnore.add(filename);
            }
        });
        rulesContainer.getIgnored().addAll(newIgnore);
        log.info("Total analyse {} targets.", stuff.size());
        Options.v().set_process_dir(new ArrayList<>(stuff));
        return new ArrayList<>(stuff);
    }

    public void addBasicClasses() {
        List<String> basicClasses = rulesContainer.getBasicClasses();
        for (String cls : basicClasses) {
            Scene.v().addBasicClass(cls, HIERARCHY);
        }
    }

    public void save() {
        log.info("Start to save data.");
        long start = System.nanoTime();

        dataContainer.save2CSV();
        dataContainer.save2Neo4j();
        clean();
        log.info("Save data cost {} seconds."
                , TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start));
    }

    public Map<String, String> getJdkDependencies(String all) {
        String javaHome = System.getProperty("java.home");

        String[] jre;
        if ("true".equals(all)) {
            jre = new String[]{"../lib/dt.jar", "../lib/sa-jdi.jar", "../lib/tools.jar",
                    "../lib/jconsole.jar", "lib/resources.jar", "lib/rt.jar", "lib/jsse.jar",
                    "lib/jce.jar", "lib/charsets.jar", "lib/ext/cldrdata.jar", "lib/ext/dnsns.jar",
                    "lib/ext/jaccess.jar", "lib/ext/localedata.jar", "lib/ext/nashorn.jar",
                    "lib/ext/sunec.jar", "lib/ext/sunjce_provider.jar", "lib/ext/sunpkcs11.jar",
                    "lib/ext/zipfs.jar", "lib/management-agent.jar"};
        } else {// 对于正常分析其他的jar文件，不需要全量jdk依赖的分析，暂时添加这几个
            jre = new String[]{"lib/rt.jar", "lib/jce.jar", "lib/ext/nashorn.jar"};
        }
        Map<String, String> exists = new HashMap<>();
        for (String cp : jre) {
            String path = String.join(File.separator, javaHome, cp);
            File file = new File(path);
            if (file.exists()) {
                exists.put(FileUtils.getFileMD5(file), path);
            }
        }
        log.info("Load " + exists.size() + " jre jars.");
        return exists;
    }

    public void clean() {
        try {
            File cacheDir = new File(GlobalConfiguration.CACHE_PATH);
            File[] files = cacheDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.getName().endsWith(".csv")) {
                        Files.deleteIfExists(file.toPath());
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}