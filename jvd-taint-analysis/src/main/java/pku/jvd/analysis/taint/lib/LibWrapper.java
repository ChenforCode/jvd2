package pku.jvd.analysis.taint.lib;

import soot.*;
import soot.jimple.toolkits.annotation.purity.DirectedCallGraph;
import soot.jimple.toolkits.annotation.purity.SootMethodFilter;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.toolkits.graph.BriefUnitGraph;

import java.io.IOException;
import java.util.*;

public class LibWrapper extends SceneTransformer {
// hashmap to store the results

    @Override
    protected void internalTransform(String arg0, Map arg1) {
        Scene.v();
        CallGraph cg = Scene.v().getCallGraph();
        Body main = Scene.v().getMainClass().getMethodByName("main").getActiveBody();
        System.out.println("application classes size==" + Scene.v().getApplicationClasses().size());
        SootMethodFilter filter = new SootMethodFilter() {
            @Override
            public boolean want(SootMethod method) {
                if (method.isJavaLibraryMethod()
                        || (method.isNative())
                        || method.getName().equals("source")
                        || method.getName().equals("sink")) {
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

        SootMethod head;
        if (dcg.size() == 0) {
            head = main.getMethod();
        } else {
            head = (SootMethod) dcg.getHeads().get(0);
        }


        Set<SootMethod> dfsStack = new HashSet<>();
        Set<SootMethod> visitedNodes = new HashSet<>();
        List<SootMethod> sortedMethods = new ArrayList<>(dcg.size());
        //遍历集合中的起始方法,进行递归搜索DFS,通过逆拓扑排序,调用链的最末端排在最前面,
        // 这样才能实现入参,返回值,函数调用链之间的污点影响
        try {
            if (dcg.size() == 0) {
                work(head);
            } else {
                dfsTsort(sortedMethods, visitedNodes, dfsStack, head, dcg);
                for (SootMethod node : sortedMethods) {
                    work(node);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void dfsTsort(List<SootMethod> sortedMethods, Set<SootMethod> visitedNodes, Set<SootMethod> dfsStack, SootMethod node, DirectedCallGraph dcg) {

        if (dfsStack.contains(node)) {
            return;
        }
        if (visitedNodes.contains(node)) {
            return;
        }
        //根据起始方法，取出被调用的方法集
        List<SootMethod> outgoingRefs = dcg.getSuccsOf(node);
        if (outgoingRefs == null) {
            return;
        }
        dfsStack.add(node);
        for (SootMethod child : outgoingRefs) {
            dfsTsort(sortedMethods, visitedNodes, dfsStack, child, dcg);
        }
        dfsStack.remove(node);
        visitedNodes.add(node);//记录已被探索过的方法，用于在上层调用遇到重复方法时可以跳过
        sortedMethods.add(node);//递
    }

    //对每一个method进行work
    private void work(SootMethod method) throws IOException {
        BriefUnitGraph g = new BriefUnitGraph(method.getActiveBody());
        new LibAnalysis(g, method.getActiveBody(), method);
    }
}
