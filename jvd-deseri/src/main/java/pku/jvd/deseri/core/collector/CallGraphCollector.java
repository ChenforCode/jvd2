package pku.jvd.deseri.core.collector;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import lombok.Setter;
import org.springframework.stereotype.Service;
import pku.jvd.deseri.core.container.DataContainer;
import pku.jvd.deseri.core.data.Context;
import pku.jvd.deseri.core.switcher.Switcher;
import pku.jvd.deseri.core.toolkit.PollutedVarsPointsToAnalysis;
import pku.jvd.deseri.dal.caching.bean.ref.MethodReference;
import soot.Modifier;
import soot.SootMethod;

@Service
@Setter
public class CallGraphCollector {
    private static final Log log = LogFactory.get(CallGraphCollector.class);

//    @Async("multiCallGraphCollector")
    public void collect(MethodReference methodRef, DataContainer dataContainer){
        try{
            SootMethod method = methodRef.getMethod();
            if(method == null) return; // 提取不出内容，不分析

            if(method.isPhantom() || methodRef.isSink()
                    || methodRef.isIgnore() || method.isAbstract()
                    || Modifier.isNative(method.getModifiers())){
                methodRef.setInitialed(true);
                return; // sink点为不动点，无需分析该函数内的调用情况  native/抽象函数没有具体的body
            }

            if(method.isStatic() && method.getParameterCount() == 0){
                // 静态函数 且 函数入参数量为0 此类函数
                // 对于反序列化来说 均不可控 不进行分析
                methodRef.setInitialed(true);
                return;
            }

            log.debug(method.getDeclaringClass().getName()+" "+method.getName());

            Context context = Context.newInstance(method.getSignature(), methodRef);

            PollutedVarsPointsToAnalysis pta =
                    Switcher.doMethodAnalysis(
                            context, dataContainer,
                            method, methodRef);
            context.clear();

        }catch (RuntimeException e){
            e.printStackTrace();
        }
    }

}
