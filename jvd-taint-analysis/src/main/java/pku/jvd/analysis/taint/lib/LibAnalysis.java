package pku.jvd.analysis.taint.lib;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;
import pku.jvd.analysis.taint.abstraction.FlowAbstraction;

import java.io.IOException;
import java.util.*;

public class LibAnalysis extends ForwardFlowAnalysis<Unit, Set<FlowAbstraction>> {
    private Body body;
    private SootMethod method;
    private int index = 0;

    public LibAnalysis(UnitGraph g, Body body, SootMethod sootMethod) throws IOException {
        super(g);
        LibUtil.classes.add(sootMethod.getDeclaringClass().getName());
        this.body = body;
        this.method = sootMethod;
        this.doAnalyis();
    }

    public void doAnalyis() {
        super.doAnalysis();
    }

    @Override
    protected void flowThrough(Set<FlowAbstraction> flowAbstractions, Unit d, Set<FlowAbstraction> a1) {
        Stmt s = (Stmt) d;//获取语句
        if (s instanceof JInvokeStmt) {//非赋值调用函数
            JInvokeStmt stmt = (JInvokeStmt) s;
            SootMethod method = stmt.getInvokeExpr().getMethod();
            if (method.isJavaLibraryMethod()) {
                LibUtil.libs.add(method.getSignature());
            }
        } else if (s instanceof JAssignStmt) {//赋值语句
            JAssignStmt as = (JAssignStmt) s;
            Value rightOp = as.getRightOp();
            Value leftOp = as.getLeftOp();
            if (rightOp instanceof InvokeExpr) {
                InvokeExpr expr = (InvokeExpr) rightOp;
                SootMethod method = expr.getMethod();
                if (method.isJavaLibraryMethod()) {
                    LibUtil.libs.add(method.getSignature());
                }
            }
        }
    }

    @Override
    protected Set<FlowAbstraction> newInitialFlow() {
        return new HashSet<FlowAbstraction>();
    }

    @Override
    protected void merge(Set<FlowAbstraction> in1, Set<FlowAbstraction> in2, Set<FlowAbstraction> out) {
        out.addAll(in1);
        out.addAll(in2);
    }

    @Override
    protected void copy(Set<FlowAbstraction> source, Set<FlowAbstraction> dest) {
        dest.clear();
        dest.addAll(source);
    }
}
