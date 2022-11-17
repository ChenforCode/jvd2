package pku.jvd.analysis.taint.lib;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileWriter;
import soot.*;
import soot.options.Options;

import java.io.File;
import java.util.*;

public class LibUtil {

    public static Set<String> classes = new HashSet<>();
    public static Set<String> libs = new HashSet<>();

    public static void initSootOptions() {
//        String classesDir = "/Users/pkucoder/pkucoder/北京大学/反序列化/test/juliet-sql/target/juliet-sql-1.2.0.jar";
//        String classesDir = "/Users/pkucoder/pkucoder/北京大学/反序列化/test/juliet-xss-sql/target/juliet-xss-sql-1.2.0.jar";
//        String classesDir = "/Users/pkucoder/pkucoder/北京大学/反序列化/test/juliet-xss/target/juliet-xss-1.2.0.jar";
//        String classesDir = "/Users/pkucoder/projects/idea_project/welldone/target/welldone-0.0.1-SNAPSHOT.jar";
        String classesDir = "/Users/pkucoder/pkucoder/北京大学/反序列化/jvd/TaintAnalysis/targetsBin/";
        String jreDir = System.getProperty("java.home") + "/lib/jce.jar";
        String jceDir = System.getProperty("java.home") + "/lib/rt.jar";
        String path = jreDir + File.pathSeparator + jceDir + File.pathSeparator + classesDir;
        Scene.v().setSootClassPath(path);

        Pack wjtp = PackManager.v().getPack("wjtp");
        wjtp.add(new Transform("wjtp.profiler", new LibWrapper()));
        Options.v().set_verbose(false);
        Options.v().setPhaseOption("jb", "use-original-names:true");
        Options.v().set_keep_line_number(true);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_process_dir(Arrays.asList(classesDir));
        Scene.v().loadNecessaryClasses();
    }


    public static void main(String[] args) {
        initSootOptions();
        PackManager.v().runPacks();
//
        File file = new File("lib.txt");
        if (file.exists()) {
            file.delete();
        }
        File lib = FileUtil.touch(file);
        FileWriter fileWriter = new FileWriter(lib);
        for (String s : LibUtil.libs) {
            fileWriter.append(s + "\n");
        }

        System.out.println("result lib:" + LibUtil.libs.size());
        System.out.println("result class kind:" + LibUtil.classes.size());
    }

}
