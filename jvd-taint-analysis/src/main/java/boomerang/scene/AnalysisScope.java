package boomerang.scene;

import boomerang.Query;
import boomerang.scene.CallGraph.Edge;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Set;
public abstract class AnalysisScope {

  //private static final Logger LOGGER = LoggerFactory.getLogger(AnalysisScope.class);
  private CallGraph cg;
  private boolean scanLibraryClasses = false;

  public static final Log log = LogFactory.get(AnalysisScope.class);

  public AnalysisScope(CallGraph cg) {
    this.cg = cg;
  }

  private final Set<Query> seeds = Sets.newHashSet();

  private Collection<Method> processed = Sets.newHashSet();
  private int statementCount;

  public void setScanLibraryClasses(boolean enabled) {
    scanLibraryClasses = enabled;
  }

  public Set<Query> computeSeeds() {
    Collection<Method> entryPoints = cg.getEntryPoints();
    log.info("Computing seeds starting at {} entry method(s).", entryPoints.size());
    Stopwatch watch = Stopwatch.createStarted();
    LinkedList<Method> worklist = Lists.newLinkedList();
    worklist.addAll(entryPoints);
    while (!worklist.isEmpty()) {
      Method m = worklist.pop();
      if (!processed.add(m)) {
        continue;
      }
      //log.trace("Processing {}", m);
      for (Statement u : m.getStatements()) {
        statementCount++;
        if (u.containsInvokeExpr()) {
          Collection<Edge> edgesOutOf = cg.edgesOutOf(u);
          for (Edge e : edgesOutOf) {
            Method tgt = e.tgt();
            if (!scanLibraryClasses && !tgt.getDeclaringClass().isApplicationClass()) continue;

            if (!processed.contains(tgt)) {
              worklist.add(tgt);
            }
          }
        }
        for (Statement succ : u.getMethod().getControlFlowGraph().getSuccsOf(u)) {
          seeds.addAll(generate(new ControlFlowGraph.Edge(u, succ)));
        }
      }
    }
    log.info("Found {} seeds in {} in {} LOC .", seeds.size(), watch, statementCount);

    return seeds;
  }

  protected boolean analyseClassInitializers() {
    return false;
  }

  protected abstract Collection<? extends Query> generate(ControlFlowGraph.Edge seed);
}
