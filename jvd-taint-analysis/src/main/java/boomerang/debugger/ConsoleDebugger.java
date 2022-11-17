package boomerang.debugger;

import boomerang.Query;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import wpds.impl.Weight;
public class ConsoleDebugger<W extends Weight> extends Debugger<W> {
  public static final Log log = LogFactory.get(ConsoleDebugger.class);
  public void done(
      java.util.Map<boomerang.ForwardQuery, boomerang.solver.ForwardBoomerangSolver<W>>
          queryToSolvers) {
    int totalRules = 0;
    for (Query q : queryToSolvers.keySet()) {
      totalRules += queryToSolvers.get(q).getNumberOfRules();
    }
    for (Query q : queryToSolvers.keySet()) {
      queryToSolvers.get(q).debugOutput();
      //            for (Method m : queryToSolvers.get(q).getReachableMethods()) {
      //                logger.debug(m + "\n" +
      // Joiner.on("\n\t").join(queryToSolvers.get(q).getResults(m).cellSet()));
      //            }
      queryToSolvers.get(q).debugOutput();
    }
  };
}
