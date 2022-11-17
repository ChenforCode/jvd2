package pku.jvd.deseri;

import cn.chenforcode.common.CommonArgs;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import pku.jvd.deseri.config.GlobalConfiguration;
import pku.jvd.deseri.core.Analyser;
import pku.jvd.deseri.core.Search;
import pku.jvd.deseri.exception.CommonException;
import pku.jvd.deseri.exception.JDKVersionErrorException;
import pku.jvd.deseri.util.ArgumentEnum;
import pku.jvd.deseri.util.FileUtils;
import pku.jvd.deseri.util.JavaVersion;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@Component
public class DeseriMainService {
    private static final Log log = LogFactory.get(DeseriMainService.class);
    @Autowired
    private Analyser analyser;
    @Autowired
    private Search search;
    private Properties props = new Properties();

    @Autowired
    private ExecutorService executorService;

    public void runDeseriAnalysis(CommonArgs commonArgs) {
        try {
            if (!JavaVersion.isJDK8()) {
                throw new JDKVersionErrorException("Error JDK version. Please using JDK8.");
            }
            long start = System.nanoTime();
            loadProperties("deseri/config/settings.properties");
            applyOptions(commonArgs);
            if (!commonArgs.getSearch().equals("true")) {
                analyser.run(props);
            }
            Future<?> commonRes = executorService.submit(() -> {
                search.searchCommon();
                search.searchCVE();
            });
            //common search的搜索时常最多为120s，否则异常
            commonRes.get(600, TimeUnit.SECONDS);
            log.info("Total Cost {} seconds."
                    , TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start));
        } catch (JDKVersionErrorException e) {
            log.info(e.getMessage());
        } catch (CommonException e) {
            log.error(e.getMsg());
        } catch (Exception e) {
            log.info(e.getMessage());
        }
    }


    private void

    applyOptions(CommonArgs args) {
        //检查三个的数量
        int argsCount = 0;
        if (args.getProcessJDK() != null) {
            argsCount++;
        }
        if (args.getExcludeJDK() != null) {
            argsCount++;
        }
        if (argsCount > 1) {
            throw new CommonException("processJDK, excludeJDK两个参数只能使用一个");
        }
        if (args.getProcessPath() != null) {
            props.setProperty(ArgumentEnum.TARGET.toString(), args.getProcessPath());
        }
        if (args.getExcludeJDK() != null) {
            if (props.get(ArgumentEnum.TARGET.toString()).equals("default-path")) {
                throw new CommonException("请输入processPath");
            }
            props.setProperty(ArgumentEnum.EXCLUDE_JDK.toString(), args.getExcludeJDK());
        }
        if (args.getProcessJDK() != null) {
            if (props.get(ArgumentEnum.TARGET.toString()).equals("default-path")) {
                throw new CommonException("请输入processPath");
            }
            props.setProperty(ArgumentEnum.IS_JDK_PROCESS.toString(), args.getProcessJDK());
        }
        GlobalConfiguration.DEBUG = "true".equals(props.getProperty(ArgumentEnum.SET_DEBUG_ENABLE.toString(), "false"));
        GlobalConfiguration.IS_FULL_CALL_GRAPH_CONSTRUCT = "true".equals(props.getProperty(ArgumentEnum.IS_FULL_CALL_GRAPH_CREATE.toString(), "false"));

        String target = props.getProperty(ArgumentEnum.TARGET.toString());

        // 支持绝对路径 issue 7
        if (target != null && !FileUtils.fileExists(target)) {
            target = String.join(File.separator, System.getProperty("user.dir"), target);
            if (!FileUtils.fileExists(target)) {
                throw new IllegalArgumentException("target not exists!");
            }
        }

        String libraries = props.getProperty(ArgumentEnum.LIBRARIES.toString());
        if (libraries != null) {
            if (FileUtils.fileExists(libraries)) {
                GlobalConfiguration.LIBS_PATH = libraries;
            } else {
                libraries = String.join(File.separator, System.getProperty("user.dir"), libraries);
                if (FileUtils.fileExists(libraries)) {
                    GlobalConfiguration.LIBS_PATH = libraries;
                }
            }
        }
    }

    private void loadProperties(String filepath) {
        try (Reader reader = new FileReader(filepath)) {
            props.load(reader);
        } catch (IOException e) {
            throw new IllegalArgumentException("Settings.properties file not found!");
        }
    }
}
