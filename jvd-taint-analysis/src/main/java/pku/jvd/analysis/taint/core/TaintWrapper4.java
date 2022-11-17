package pku.jvd.analysis.taint.core;


import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import pku.jvd.analysis.taint.abstraction.EndpointConstant;
import pku.jvd.analysis.taint.abstraction.FlowAbstraction;
import pku.jvd.analysis.taint.abstraction.SQLEndpointConstant;
import pku.jvd.analysis.taint.abstraction.XSSEndpointConstant;
import soot.*;
import soot.jimple.Stmt;
import soot.jimple.toolkits.annotation.logic.Loop;
import soot.jimple.toolkits.annotation.purity.DirectedCallGraph;
import soot.jimple.toolkits.annotation.purity.SootMethodFilter;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.LoopNestTree;
import soot.toolkits.graph.SlowPseudoTopologicalOrderer;

import java.util.*;

public class TaintWrapper4 extends SceneTransformer {

    private static final Log log = LogFactory.get(TaintWrapper4.class);
    private String vuln = "all";

    public static Map<String, Map<FlowAbstraction, List<FlowAbstraction>>> taintMap = new HashMap<>();
    public static Set<FlowAbstraction> sourceSet = new HashSet<>();
    public static Map<String, Set<FlowAbstraction>> sourceMap = new HashMap<>();

    public static Set<String> sourceMethod = new HashSet<>();
    public static Set<String> sinkMethod = new HashSet<>();
    public static Set<String> ignoreMethod = new HashSet<>();

    static {
        sourceMethod.add("getProperty");
        sinkMethod.add("execute");
        ignoreMethod.add("getDBConnection");
        ignoreMethod.add("getConnection");
        ignoreMethod.add("log");

    }

    public TaintWrapper4(String vuln) {
        this.vuln = vuln;
    }

    public TaintWrapper4() {
    }

    @Override
    protected void internalTransform(String arg0, Map arg1) {
        Scene.v();
        CallGraph cg = Scene.v().getCallGraph();
//        Body main = Scene.v().getMainClass().getMethodByName("main").getActiveBody();
        SootMethodFilter filter = new SootMethodFilter() {

            @Override
            public boolean want(SootMethod method) {
                if (method.isJavaLibraryMethod()
                        || (method.isNative())
                        || method.getName().equals("source")
                        || method.getName().equals("sink")
                        || sinkMethod.contains(method.getName())
                        || sourceMethod.contains(method.getName())
                        || ignoreMethod.contains(method.getName())) {
                    ArrayList<Integer> objects = new ArrayList<>();
                    objects.sort((Comparator.comparingInt(o -> o)));
                    return false;
                }
                return true;
            }
        };

        Iterator<MethodOrMethodContext> heads = cg.sourceMethods();

        List<SootMethod> methods = new ArrayList<>();
        heads.forEachRemaining(e -> {
            methods.add(e.method());
        });

        DirectedCallGraph dcg = new DirectedCallGraph(cg, filter, methods.iterator(), true);

        log.info("Dcg size={}", dcg.size());
        for (SootMethod object : dcg) {
            SootMethod method = object;
            Map<FlowAbstraction, List<FlowAbstraction>> res = new HashMap<>();
            taintMap.put(method.getSignature(), res);
        }
        List<SootMethod> sortedMethods = SlowPseudoTopologicalOrderer.v().newList(dcg, true);
        log.info("Dcg topological order complete, sorted method size = {}", sortedMethods.size());
        if (sortedMethods == null || sortedMethods.size() == 0) {
            return;
        }
        for (SootMethod sortedMethod : sortedMethods) {
            work(sortedMethod);
        }

        //处理staticfield，绑定functionname
        for(String funName : taintMap.keySet()){//each function
            List<FlowAbstraction> newList = new ArrayList<>();
            Map<FlowAbstraction, List<FlowAbstraction>> sourceMap = taintMap.get(funName);
            for(FlowAbstraction source : sourceMap.keySet()) {//each source
                List<FlowAbstraction> taintedList = sourceMap.get(source);
                for(FlowAbstraction item : taintedList){//each tainted item
                    if (item.isStatic())//出口是static
                    {
                        for(String subFunName : taintMap.keySet()) {//遍历所有的函数，看是否有任何函数被这个static污染
                            Map<FlowAbstraction, List<FlowAbstraction>> subSourceMap = taintMap.get(subFunName);
                            for(FlowAbstraction subSource : subSourceMap.keySet()){//遍历
                                if (subSource.isTaintedByStatic() && !subSource.isStaticModified() ){//有函数被static污染
                                    FlowAbstraction flowAbstraction = new FlowAbstraction(item.getSource(),item.getFuncName(),item.getDestIndex());
                                    flowAbstraction.setLocal(item.getLocal());
                                    if(subSource.getStaticField().toString().equals(item.getLocal().toString()) ){
                                        //确认是被当前正在分析的static污染
                                        //创建一个新的flowabs，放入newlist
                                        if(subFunName != funName)//避免死锁
                                            flowAbstraction.setFuncName(subFunName);
                                        newList.add(flowAbstraction);
                                    }
                                }
                            }
                        }
                    }else{
                        newList.add(item);
                    }
                }
                //用newlist替换原本的list，达到绑定函数的目的
                taintedList.clear();
                for (FlowAbstraction f : newList)
                    taintedList.add(f);
            }
        }

    }

    //对每一个method进行work
    private void work(SootMethod method) {
        String name = method.getSignature();
//        System.out.println("\n\n"+name);
        BriefUnitGraph g = new BriefUnitGraph(method.getActiveBody());
        EndpointConstant endpointConstant;
        Set<Stmt> beAnalyzed = new HashSet<>();
//        Set<Stmt> loopEntryStmts = new HashSet<>();
//        Set<Stmt> loopExitStmts = new HashSet<>();
        List<Stmt> loopStmts = new ArrayList<>();
        LoopNestTree loopNestTree = new LoopNestTree(method.getActiveBody());
        Map<Stmt, List<Stmt>> loopMaps = new HashMap<>();
        for (Loop loop : loopNestTree)
        {
//            loopEntryStmts.add(loop.getHead());
            loopStmts = loop.getLoopStatements();
//            loopExitStmts.addAll(loop.targetsOfLoopExit((Stmt)(loop.getLoopExits().toArray()[0])));
            loopMaps.put(loop.getHead(), loopStmts);
        }

        if (vuln.equals("xss")) {
            endpointConstant = new XSSEndpointConstant();
        } else if (vuln.equals("sql")) {
            endpointConstant = new SQLEndpointConstant();
        } else {
            endpointConstant = new EndpointConstant();
        }
        TaintAnalysis4 reach = new TaintAnalysis4(g, taintMap, sourceMap, method.getActiveBody(), method, endpointConstant, loopMaps, beAnalyzed);
        taintMap.put(name, reach.argsChain);
    }
}