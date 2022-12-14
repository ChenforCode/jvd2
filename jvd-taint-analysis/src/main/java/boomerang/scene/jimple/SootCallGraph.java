package boomerang.scene.jimple;

import boomerang.scene.CallGraph;
import boomerang.scene.Statement;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import soot.Scene;
import soot.SootMethod;

public class SootCallGraph extends CallGraph {
  //Logger LOGGER = LoggerFactory.getLogger(SootCallGraph.class);
  private static final Log log = LogFactory.get(SootCallGraph.class);
  public SootCallGraph() {
    soot.jimple.toolkits.callgraph.CallGraph callGraph = Scene.v().getCallGraph();
    for (soot.jimple.toolkits.callgraph.Edge e : callGraph) {
      if (e.src().hasActiveBody() && e.tgt().hasActiveBody() && e.srcStmt() != null) {
        Statement callSite = JimpleStatement.create(e.srcStmt(), JimpleMethod.of(e.src()));
        if (callSite.containsInvokeExpr()) {
          log.trace("Call edge from {} to target method {}", callSite, e.tgt());
          this.addEdge(new Edge(callSite, JimpleMethod.of(e.tgt())));
        }
      }
    }
    for (SootMethod m : Scene.v().getEntryPoints()) {
      if (m.hasActiveBody()) this.addEntryPoint(JimpleMethod.of(m));
    }
  }
}
