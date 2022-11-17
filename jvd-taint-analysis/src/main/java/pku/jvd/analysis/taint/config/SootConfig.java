package pku.jvd.analysis.taint.config;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.DefaultBoomerangOptions;
import boomerang.Query;
import boomerang.results.BackwardBoomerangResults;
import boomerang.scene.*;
import boomerang.scene.jimple.BoomerangPretransformer;
import boomerang.scene.jimple.SootCallGraph;
import pku.jvd.analysis.pointer.PtrTransformer;
import pku.jvd.analysis.taint.core.pointerAnalysisTransformerFast;
import soot.*;
import soot.options.Options;
import pku.jvd.analysis.taint.core.TaintWrapper4;
import pku.jvd.analysis.taint.core.pointerAnalysisTransformer;
import wpds.impl.Weight;

import java.io.File;
import java.util.*;

public class SootConfig {
    public static void initSootConfiguration(String classesDir, String vuln, String alias) {
        String jreDir = System.getProperty("java.home") + "/lib/jce.jar";
        String jceDir = System.getProperty("java.home") + "/lib/rt.jar";
        String path = jreDir + File.pathSeparator + jceDir + File.pathSeparator + classesDir;
        Scene.v().setSootClassPath(path);
        Options.v().set_verbose(false);
        Options.v().setPhaseOption("jb", "use-original-names:true");
        Options.v().set_keep_line_number(true);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_process_dir(Arrays.asList(classesDir));
        Options.v().set_verbose(false);
        Scene.v().loadNecessaryClasses();

        Pack wjtp = PackManager.v().getPack("wjtp");
        //NEW: add pointer analysis
        //Pointer Analysis package, pointer analysis scope
        if(alias.equals("true1")){
            //wjtpptr.add(new Transform("wjtp.PtrTransformer", new PtrTransformer()));
            Transform transform = new Transform("wjtp.ifds", new pointerAnalysisTransformerFast());
            PackManager.v().getPack("wjtp").add(transform);
            PackManager.v().getPack("cg").apply();
            BoomerangPretransformer.v().apply();
            //PackManager.v().getPack("wjtp").apply();
        }
        else if(alias.equals("true2")){
            //wjtpptr.add(new Transform("wjtp.PtrTransformer", new PtrTransformer()));
            Transform transform = new Transform("wjtp.ifds", new pointerAnalysisTransformer());
            PackManager.v().getPack("wjtp").add(transform);
            PackManager.v().getPack("cg").apply();
            BoomerangPretransformer.v().apply();
            //PackManager.v().getPack("wjtp").apply();
        }
        wjtp.add(new Transform("wjtp.profiler", new TaintWrapper4(vuln)));
        //Scene.v().loadNecessaryClasses();
    }

    public static void initSootConfiguration(String classesDir) {
        String jreDir = System.getProperty("java.home") + "/lib/jce.jar";
        String jceDir = System.getProperty("java.home") + "/lib/rt.jar";
        String path = jreDir + File.pathSeparator + jceDir + File.pathSeparator + classesDir;
        Scene.v().setSootClassPath(path);

        Pack wjtp = PackManager.v().getPack("wjtp");
        wjtp.add(new Transform("wjtp.profiler", new TaintWrapper4()));
        Options.v().set_verbose(false);
        Options.v().setPhaseOption("jb", "use-original-names:true");
        Options.v().set_keep_line_number(true);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_process_dir(Arrays.asList(classesDir));
        Options.v().set_verbose(false);
        Scene.v().loadNecessaryClasses();
    }

    public static void setEntryPoints(List<SootMethod> sqlEntryPoints) {
        Scene.v().setEntryPoints(sqlEntryPoints);
    }

    public static void setMainClass(String mainClass) {
        Options.v().set_main_class(mainClass);
    }

    public static SootMethod getSootMethodBySig(String sig) {
        try {
            return Scene.v().getMethod(sig);
        } catch (Exception e) {
            return null;
        }
    }

    public static List<SootMethod> getSootMethodsBySigs(List<String> sigs) {
        List<SootMethod> sootMethods = new ArrayList<>();
        try {
            for (String sig : sigs) {
                sootMethods.add(Scene.v().getMethod(sig));
            }
            return sootMethods;
        } catch (Exception e) {
            return null;
        }
    }

    public static SootMethod getSootMethodsBySig(String sig) {
        return Scene.v().getMethod(sig);
    }
}
