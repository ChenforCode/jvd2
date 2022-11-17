package pku.jvd.deseri.core.scanner;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import pku.jvd.deseri.core.collector.CallGraphCollector;
import pku.jvd.deseri.core.container.DataContainer;
import pku.jvd.deseri.dal.caching.bean.ref.MethodReference;
import pku.jvd.deseri.dal.caching.service.MethodRefService;

import java.util.ArrayList;
import java.util.Collection;

@Data
@Component
public class CallGraphScanner {
    private static final Log log = LogFactory.get(CallGraphScanner.class);

    @Autowired
    public MethodRefService methodRefService;
    @Autowired
    public DataContainer dataContainer;

    @Autowired
    public CallGraphCollector collector;

//    @Resource
//    @Qualifier("multiCallGraphCollector")
//    private Executor executor;

    public static int total;
    public static int split;
    public static int current;

    public void run() {
        collect();
        save();
    }

    public void collect() {
        Collection<MethodReference> targets =
                new ArrayList<>(dataContainer.getSavedMethodRefs().values());
//        log.info("Load necessary method refs.");
//        dataContainer.loadNecessaryMethodRefs();
        log.info("Build call graph. START!");
        total = targets.size();
        split = total / 10;
        split = split==0?1:split;
        int count = 0;
        for (MethodReference target : targets) {
            if(count%split == 0){
                log.info("Status: {}%, Remain: {}", String.format("%.1f",count*0.1/total*1000), (total-count));
            }
            collector.collect(target, dataContainer);
            count++;
        }
        log.info("Status: 100%, Remain: 0");
        log.info("Build call graph. DONE!");
    }

    public void save() {
        log.info("Save remained data to graphdb. START!");
        dataContainer.save("class");
        dataContainer.save("method");
        dataContainer.save("has");
        dataContainer.save("call");
        dataContainer.save("alias");
        dataContainer.save("extend");
        dataContainer.save("interfaces");
        log.info("Save remained data to graphdb. DONE!");
    }
}