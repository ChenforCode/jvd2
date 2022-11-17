package pku.jvd.analysis.taint.core;

import pku.jvd.analysis.taint.search.ChainNode;
import pku.jvd.analysis.taint.search.GadgetChain;
import soot.*;
import soot.options.Options;
import pku.jvd.analysis.taint.search.ChainDiscovery;

import java.io.File;
import java.util.Arrays;

public class Driver4 {
    public static void main(String[] args) {
        String classesDir = "/Users/lxpig/jvd/jvd-taint-analysis/testClassFiles/singleTest";
        String mainClass = "cn.chenforcode.longPath";
        String jreDir = System.getProperty("java.home") + "/lib/jce.jar";
        String jceDir = System.getProperty("java.home") + "/lib/rt.jar";
        System.out.println(jceDir);
        String path = jreDir + File.pathSeparator + jceDir + File.pathSeparator + classesDir;
        Scene.v().setSootClassPath(path);

        Pack wjtp = PackManager.v().getPack("wjtp");
        wjtp.add(new Transform("wjtp.profiler", new TaintWrapper4()));
        Options.v().setPhaseOption("jb", "use-original-names:true");
        Options.v().set_keep_line_number(true);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_main_class(mainClass);
        Options.v().set_process_dir(Arrays.asList(classesDir));
        Scene.v().loadNecessaryClasses();
        SootClass mainClass1 = Scene.v().getMainClass();
        System.out.println(mainClass1);

        PackManager.v().runPacks();


        //搜索问题
        System.out.println(TaintWrapper4.taintMap.size());
        ChainDiscovery chainDiscovery = new ChainDiscovery(TaintWrapper4.taintMap, TaintWrapper4.sourceMap);
        chainDiscovery.discovery();
        for(GadgetChain i:chainDiscovery.chains){
          System.out.println(i.getSource().getSource()+"->");
          for(ChainNode j : i.getChain()){
            System.out.println(j.toString());
          }
         System.out.println('\n');
        }
        System.out.println("total chain: "+chainDiscovery.chains.size());
    }
}
