package pku.jvd.analysis.taint.core;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.DefaultBoomerangOptions;
import boomerang.Query;
import boomerang.results.BackwardBoomerangResults;
import boomerang.scene.*;
import boomerang.scene.jimple.JimpleVal;
import boomerang.scene.jimple.SootCallGraph;
import boomerang.util.AccessPath;
import soot.Scene;
import soot.SceneTransformer;
import soot.Value;
import wpds.impl.Weight;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;

import java.util.*;

public class pointerAnalysisTransformerFast extends SceneTransformer {
    private static final Log log = LogFactory.get(pointerAnalysisTransformerFast.class);
    public static Set<Set<Value>> aliasSetRes = new HashSet<>();
    public static SootCallGraph sootCallGraph;
    public boolean ifTransformed = false;

    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        if(ifTransformed){
            return;
        }
        ifTransformed = true;
        //calculate the compute scope
        sootCallGraph = new SootCallGraph();
        AnalysisScope scope = new AnalysisScope(sootCallGraph) {
            @Override
            protected Collection<? extends Query> generate(ControlFlowGraph.Edge cfgEdge) {
                Statement statement = cfgEdge.getTarget();
                //计算两种可能含有存在别名关系变量的语句：invoke and assign
                if (statement.containsInvokeExpr() && statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    List<Val> list = statement.getInvokeExpr().getArgs();
                    Collection<Query> queryCollection = new HashSet<>();
                    for(Val arg : list){
                        BackwardQuery backwardQuery = BackwardQuery.make(cfgEdge, arg);
                        queryCollection.add(backwardQuery);
                    }
                    return queryCollection;
                }
                if(statement.isAssign()){
                    Val v = statement.getRightOp();
                    if(!v.isLocal()){
                        return Collections.emptySet();
                    }
                    return Collections.singleton(BackwardQuery.make(cfgEdge, v));
                }
                return Collections.emptySet();
            }
        };


        //生成需要进行分析的Value集合并包装成query(s)
        Collection<Query> seeds = scope.computeSeeds();
        int seedSize = seeds.size();
        double cnt = 0;
        int process = 0;


        for (Query query : seeds) {
            if( (cnt++/seedSize)*100 > process ){
                process = process + 10;
                log.info("pointer analysis progress :{}%", (process));
            }
            Boomerang solver =
                    new Boomerang(
                            sootCallGraph, SootDataFlowScope.make(Scene.v()), new DefaultBoomerangOptions()){};
            BackwardQuery bquery = (BackwardQuery) query;
            //对于函数初始化过程中的污点传播进行处理
            if(bquery.cfgEdge().getX().containsInvokeExpr() && bquery.cfgEdge().getY().isAssign()
                    && bquery.cfgEdge().getX().getInvokeExpr().isInstanceInvokeExpr()){
                if(bquery.cfgEdge().getY().getRightOp().toString().equals(bquery.cfgEdge().getX().getInvokeExpr().getBase().toString())
                        && bquery.cfgEdge().getX().getInvokeExpr().toString().contains("init")){
                    Set<Value> aliasSet = new HashSet<>();
                    for(Val v:bquery.cfgEdge().getX().getInvokeExpr().getArgs()){
                        JimpleVal jv = (JimpleVal)v;
                        aliasSet.add(jv.v);
                    }
                    JimpleVal jv = (JimpleVal) bquery.cfgEdge().getY().getLeftOp();
                    aliasSet.add(jv.v);
                    JimpleVal jv2 = (JimpleVal) bquery.cfgEdge().getX().getInvokeExpr().getBase();
                    aliasSet.add(jv2.v);
                    aliasSetRes.add(aliasSet);
                }
            }
            BackwardBoomerangResults<Weight.NoWeight> backwardQueryResults =
                    solver.solve((BackwardQuery) query);
            Set<AccessPath> apSet = backwardQueryResults.getAllAliases();
            if(apSet.isEmpty()){
                continue;
            }
            Set<Value> aliasSet = new HashSet<>();
            for(AccessPath ap : apSet){
                aliasSet.add(ap.getValue());
            }
            aliasSet.add(bquery.getValue());
            aliasSetRes.add(aliasSet);
            solver.unregisterAllListeners();
        }
        aliasSetRes.removeIf(aliasSet -> aliasSet.size() == 1);
    }

//
//    private Set<Node<ControlFlowGraph.Edge, Val>> runQuery(Collection<? extends Query> queries) {
//        final Set<Node<ControlFlowGraph.Edge, Val>> results = Sets.newHashSet();
//
//        for (final Query query : queries) {
//            Set<Value> aliasSet = new HashSet<>();
//            Boomerang solver = new Boomerang(sootCallGraph, SootDataFlowScope.make(Scene.v()), new DefaultBoomerangOptions()) {};
//            if (query instanceof BackwardQuery) {
//                //Stopwatch watch = Stopwatch.createStarted();
//                BackwardBoomerangResults<Weight.NoWeight> res = solver.solve((BackwardQuery) query);
////                globalQueryTime = globalQueryTime.plus(watch.elapsed());
////
////                LOGGER.info("Solving query took: {}", watch);
////                LOGGER.info("Expected results: {}", globalQueryTime);
//                System.out.println(res.getAllAliases());
//                for (ForwardQuery q : res.getAllocationSites().keySet()) {
//                    //System.out.println(q.var());
//                    results.add(q.asNode());
////                    for (Node<ControlFlowGraph.Edge, Val> s : solver.getSolvers().get(q).getReachedStates()) {
////                        if (s.stmt().getMethod().toString().contains("unreachable")) {
////                            throw new RuntimeException("Propagation within unreachable method found.");
////                        }
////                    }
//                }
//                if(!aliasSet.isEmpty()){
//                    aliasSet.add(((BackwardQuery) query).getValue());
//                    System.out.println("ahcdakcb"+aliasSet.toString());
//                }
////                if (queryDetector.accessPathQuery) {
////                    checkContainsAllExpectedAccessPath(res.getAllAliases());
////                }
//            }
//        }
//        return results;
//    }

}
