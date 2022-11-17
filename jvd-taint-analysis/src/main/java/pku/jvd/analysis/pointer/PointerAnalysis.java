package pku.jvd.analysis.pointer;


import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardBranchedFlowAnalysis;

public abstract class PointerAnalysis<T> extends ForwardBranchedFlowAnalysis<T> {
    public PointerAnalysis(UnitGraph graph) {
        super(graph);
    }

    public abstract boolean mayAlias(Pointer p, Stmt s, Pointer q, Stmt r);

    public abstract boolean mustAlias(Pointer p, Stmt s, Pointer q, Stmt r);
}
