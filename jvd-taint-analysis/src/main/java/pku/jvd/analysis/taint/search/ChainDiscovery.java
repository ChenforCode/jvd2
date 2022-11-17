package pku.jvd.analysis.taint.search;


import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import pku.jvd.analysis.taint.abstraction.FlowAbstraction;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @description 链条搜索主类
 **/
public class ChainDiscovery {
    private static final Log log = LogFactory.get(ChainDiscovery.class);
    //污点分析结果
    Map<String, Map<FlowAbstraction, List<FlowAbstraction>>> taintMap;
    //source信息
    Map<String, Set<FlowAbstraction>> sourceMap;
    //最终的链条结果
    public List<GadgetChain> chains = new ArrayList<>();

    public ChainDiscovery(Map<String, Map<FlowAbstraction, List<FlowAbstraction>>> taintMap,
                          Map<String, Set<FlowAbstraction>> sourceMap) {
        this.taintMap = taintMap;
        this.sourceMap = sourceMap;
    }

    //以每一个source为起点开始进行广搜
    public void discovery() {
        //存储所有的source
        for (Map.Entry<String, Set<FlowAbstraction>> entry : sourceMap.entrySet()) {
            //该方法下所有的source
            Set<FlowAbstraction> value = entry.getValue().stream().map(e -> {
                e.setFuncName(entry.getKey());
                return e;
            }).collect(Collectors.toSet());

            //以每一个source为起点开始广搜
            for (FlowAbstraction source : value) {
                discoverySource(source);
            }
        }
        Set<String> before = new HashSet<>();
        Set<String> after = new HashSet<>();
        for (GadgetChain re : chains) {
            String funcName = re.getSource().getLocationName();
            String className = funcName.split(":")[0].split("<")[1];
            before.add(className);
        }
        //对chain进行倒推，将source向前补全
        for (GadgetChain chain : chains) {
            //source存在父source，向前搜索
            if (chain.getSource().getParents() != null) {
                FlowAbstraction curSource = chain.getSource();
                //定义前半段链条
                List<ChainNode> preChain = new ArrayList<>();
                //找到真正的source
                FlowAbstraction realSource = findRealSource(curSource, preChain);
                chain.setSource(realSource);
                preChain.addAll(chain.getChain());
                chain.setChain(preChain);
            }
        }

        for (GadgetChain re : chains) {
            String funcName = re.getSource().getLocationName();
            String className = funcName.split(":")[0].split("<")[1];
            after.add(className);
        }
        before.removeAll(after);
    }

    public void discoverySource(FlowAbstraction source) {
        //为该source创建一个队列
        Queue<GadgetChain> queue = new LinkedList<>();
        //获取当前source所在func的分析结果
        Map<FlowAbstraction, List<FlowAbstraction>> curTaintMap = taintMap.get(source.getFuncName());
        //如果函数内没有该source的分析结果，直接跳过
        if (curTaintMap == null || curTaintMap.size() == 0) {
            return;
        }
        //根据分析结果获取source的流向
        List<FlowAbstraction> curTaintDirects = curTaintMap.get(source);
        //如果没有流向，直接跳过
        if (curTaintDirects == null || curTaintDirects.size() == 0) {
            return;
        }
        for (FlowAbstraction curTaintDirect : curTaintDirects) {
            //如果是返回值，则直接跳过
            if (curTaintDirect.isRetval()) {
                continue;
            }
            GadgetChain gadgetChain = new GadgetChain();
            gadgetChain.setSource(source);
            ChainNode chainNode = new ChainNode(curTaintDirect);
            List<ChainNode> chainNodeList = new ArrayList<>();
            chainNodeList.add(chainNode);
            gadgetChain.setChain(chainNodeList);
            if (curTaintDirect.isSink()) {
                //说明这里边只有两个节点，一个source，一个sink
                chains.add(gadgetChain);
            }
            //剩下的都是func的情况，需要入队
            queue.add(gadgetChain);
        }

        while (!queue.isEmpty()) {
            GadgetChain headChain = queue.poll();
            ChainNode lastNode = headChain.getChain().get(headChain.getChain().size() - 1);
            //获取lastNode所在func的分析结果
            Map<FlowAbstraction, List<FlowAbstraction>> curMap = taintMap.get(lastNode.getNode().getFuncName());
            if (curMap == null || curMap.size() == 0) {
                continue;
            }
            for (Map.Entry<FlowAbstraction, List<FlowAbstraction>> entry : curMap.entrySet()) {
                //如果函数内某个参数的位置，与当前node的destIndex保持一致，说明可以传递
                //当前node的destIndex代表谁来到这里，并且这里会出去，所以接着寻找map里边该参数的流向
                if (entry.getKey().getArgIndex() == lastNode.getNode().getDestIndex()) {
                    //找到该参数的所有流向
                    List<FlowAbstraction> nextDirects = entry.getValue();
                    if (nextDirects == null || nextDirects.size() == 0) {
                        continue;
                    }
                    for (FlowAbstraction nextDirect : nextDirects) {
                        //如果是返回值，则直接跳过
                        if (nextDirect.isRetval()) {
                            continue;
                        }
                        //创建一个新节点
                        ChainNode nextChainNode = new ChainNode(nextDirect);
                        //创建一个新链
                        GadgetChain newChain = new GadgetChain();
                        //新链的source和老链保持一致
                        newChain.setSource(headChain.getSource());
                        //将老链的list，加上一个新节点创建一个新的链
                        newChain.setChain(headChain.newChain(headChain.chain, nextChainNode));

                        if (nextDirect.isSink()) {
                            //说明这里边只有两个节点，一个source，一个sink
                            chains.add(newChain);
                        }
                        //剩下的都是func的情况，需要入队
                        queue.add(newChain);
                    }
                }
            }
        }
    }

    public FlowAbstraction findRealSource(FlowAbstraction curSource, List<ChainNode> preChain) {
        //如果当前的source没有父亲source了，那么他就是最终的curSource
        if (curSource.getParents() == null) {
            return curSource;
        }
        preChain.add(0, new ChainNode(curSource));
        //否则就继续寻找
        return findRealSource(curSource.getParents(), preChain);
    }
}
