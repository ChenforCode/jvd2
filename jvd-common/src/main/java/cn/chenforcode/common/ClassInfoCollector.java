package cn.chenforcode.common;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.SourceLocator;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ClassInfoCollector {

    //正式环境用,获取jar包中的所有入口
    public List<SootMethod> getWebEntryPoints(String jarPath) {
        List<SootMethod> entryPoints = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            if (!theClass.isPhantom()) {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) theClass.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().contains("Controller")) {
                            //找到了包含Controller的类
                            //继续往里找里边有没有mapping
                            for (SootMethod method : theClass.getMethods()) {
                                VisibilityAnnotationTag methodTag = (VisibilityAnnotationTag) method.getTag("VisibilityAnnotationTag");
                                if (methodTag != null) {
                                    for (AnnotationTag methodAnnotation : methodTag.getAnnotations()) {
                                        if (methodAnnotation.getType().contains("Mapping")) {
                                            entryPoints.add(method);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return entryPoints;
    }

    //测试环境用
    //把给出jar包的所有的bad方法全部提取出来
    public List<SootMethod> getAllTestEntryPoints(String jarPath) {
        List<SootMethod> entryPoints = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            if (!theClass.isPhantom()) {
                List<SootMethod> methods = theClass.getMethods();
                for (SootMethod method : methods) {//1月30，这里改动，想看看可不可以吧good提取出来，徐尚志
                    if (method.getSignature().contains("bad(") &&
                            !method.getSignature().contains("testcasesupport")) {
                        entryPoints.add(method);
                    }
                }
            }
        }
        return entryPoints;
    }

    //测试环境用
    //把sql相关的bad方法提取出来
    public List<SootMethod> getSQLTestEntryPoints(String jarPath) {
        List<SootMethod> entryPoints = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            if (!theClass.isPhantom()) {
                List<SootMethod> methods = theClass.getMethods();
                for (SootMethod method : methods) {
                    if (method.getSignature().contains("bad(") &&
                            !method.getSignature().contains("testcasesupport")) {
                        entryPoints.add(method);
                    }
                }
            }
        }
        return entryPoints;
    }

    //获取SQL的good方法
    public List<SootMethod> getSQLTestGoodEntryPoints(String jarPath) {
        List<SootMethod> entryPoints = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            if (!theClass.isPhantom()) {
                List<SootMethod> methods = theClass.getMethods();
                for (SootMethod method : methods) {
                    if (method.getSignature().contains("good(") &&
                            !method.getSignature().contains("testcasesupport")) {
                        entryPoints.add(method);
                    }
                }
            }
        }
        return entryPoints;
    }

    public int getClassesCount(String jarPath) {
        return SourceLocator.v().getClassesUnder(jarPath).size();
    }

    //测试环境用
    //把xss相关的bad方法提取出来
    public List<SootMethod> getXSSTestEntryPoints(String jarPath) {
        List<SootMethod> entryPoints = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            if (!theClass.isPhantom()) {
                List<SootMethod> methods = theClass.getMethods();
                for (SootMethod method : methods) {
                    if (method.getSignature().contains("bad(") &&
                            !method.getSignature().contains("testcasesupport")) {
                        entryPoints.add(method);
                    }
                }
            }
        }
        return entryPoints;
    }

    public List<SootMethod> getXSSGoodTestEntryPoints(String jarPath) {
        List<SootMethod> entryPoints = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            if (!theClass.isPhantom()) {
                List<SootMethod> methods = theClass.getMethods();
                for (SootMethod method : methods) {
                    if (method.getSignature().contains("good(") &&
                            !method.getSignature().contains("testcasesupport")) {
                        entryPoints.add(method);
                    }
                }
            }
        }
        return entryPoints;
    }

    public List<String> getClassesInJar(String jarPath) {
        List<String> allClasses = new ArrayList<>();

        for (String cl : SourceLocator.v().getClassesUnder(jarPath)) {
            SootClass theClass = Scene.v().loadClassAndSupport(cl);
            allClasses.add(theClass.getName());
        }
        return allClasses;
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        //path一律采用相对路径
//        String jarPath = "testJarFiles/juliet-sql-1.2.0.jar";
//        ClassInfoCollector collector = new ClassInfoCollector();
//
//        List<SootMethod> entryPointMethods = collector.getSQLTestEntryPoints(jarPath);
//        for (SootMethod entryPointMethod : entryPointMethods) {
//            System.out.println(entryPointMethod.getSignature());
//        }
//        System.out.println(entryPointMethods.size());
        String jarPath = "/Users/pkucoder/pkucoder/北京大学/反序列化/jvd/jvd-xvd/deseri-lib/rt.jar";
        JarFile jarFile = new JarFile(jarPath);
        Enumeration<JarEntry> e = jarFile.entries();
        List<String> res = new ArrayList<>();
        while (e.hasMoreElements()) {
            JarEntry je = e.nextElement();
            if (je.isDirectory() || !je.getName().endsWith(".class")) {
                continue;
            }
            res.add(je.getName());
        }
        System.out.println(res.size());
    }
}
