package pku.jvd.analysis.pointer;

import java.util.Iterator;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Spliterator;

import soot.*;
import soot.toolkits.graph.TrapUnitGraph;
import soot.jimple.AssignStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.internal.JInstanceFieldRef;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;

public class PtrTransformer extends SceneTransformer{

    Map<SootMethod, TargetedPointerAnalysis> methodToTapa = new HashMap<>();
    //public static boolean dumpInfo = false;
    public static String targetObjectClass = "java.lang.Object";
    public static Set<Set<String>> pointerResult = new HashSet<>();
    Set<SootMethod> methodsLeft = new HashSet<SootMethod>();
    Set<SootMethod> methodsDone = new HashSet<SootMethod>();
    public static Set<Value> allValue = new HashSet<>();
    //public boolean usePtrAnalysis = true;

    //get main method
    //do pointer analysis for relevant objects and for objects related to virtual methods
    //add static methods to methods to consider, and all possible virtual method call invocations
    //is it cheaper to do an analysis on classes before? and check if a virtual method is only defined once?
    //perhaps we should also limit packages to consider

    @Override
    protected void internalTransform(String arg0, Map<String, String> arg1) {

        try {
            methodsLeft.add(Scene.v().getMainMethod());
        }catch (Exception e){
            System.out.println("no main method");
        }
        while(methodsLeft.size() != 0){
            Set<SootMethod> methodsNext = new HashSet<SootMethod>();
            for(SootMethod method : methodsLeft){
                //处理递归调用bug
                //methodMen.add(method.hashCode());
                TargetedPointerAnalysis tpa =
                        this.pointerAnalysis(method, Scene.v().getType(targetObjectClass));
                if(tpa != null) {
                    //methodToPA.put(method, tpa);
                    methodsDone.add(method);
                    Iterator<Edge> it = Scene.v().getCallGraph().edgesOutOf(method);
                    while (it.hasNext()) {
                        methodsNext.add(it.next().tgt());
                    }
                }
                methodToTapa.put(method, tpa);
            }
            methodsNext.removeAll(methodsDone);
            methodsLeft = methodsNext;
        }
        //TODO :modify the match rule
        Set<Value> toRemove = new HashSet<>();
        for(Value v : allValue){
            boolean flag = false;
            for(Set<String> s: pointerResult){
                //TODO : modify filter rules for 'allvalue'
                if(s.contains(v.toString()) && !v.toString().contains("$stack")){
                    flag = true;
                }
            }
            if(!flag){
                toRemove.add(v);
            }
        }
        System.out.println(toRemove);
        allValue.removeAll(toRemove);
    }

/*
    protected CallGraph constructICSCG(TargetedPointerAnalysis mainTPA, CallGraph cg){
        Map<SootMethod,TargetedPointerAnalysis> methodToTPA = new HashMap<SootMethod,TargetedPointerAnalysis>();

        //for each invocation in the main method
        for(InvokeExpr e : mainTPA.invokeExprs){
            //if the invocation is not static
            if(e instanceof InstanceInvokeExpr){
                InstanceInvokeExpr iie = (InstanceInvokeExpr) e;
                //get the pointer to the target of the invocation
                Pointer p = mainTPA.valuePointer.get(iie.getBase());
                //get the invocation unit
                Unit u = mainTPA.unitToInvokeExpr.get(e);
                //for each possible object that the target pointer can point to
                for(AbstractObject o : mainTPA.getFlowBefore(u).localAssignedTo.get(p)){
                    //if o is a resolved object (i.e. not an object from another method invocation)
                    if(o instanceof NewObject){
                        NewObject newObj = (NewObject) o;
                        //get the type of the object
                        ////a possible optimisation would be to only keep one object of one type for method variables
                        Type type = newObj.getType();
                        //if the type is a type from the user program
                        if(type instanceof RefLikeType){
                            if(type instanceof RefType){
                                RefType refType = (RefType) type;
                                //get the class corresponding to the type
                                SootClass sootClass = refType.getSootClass();
                                //get the method possibly invoked
                                SootMethod method = sootClass.getMethod(iie.getMethod().getSignature());
                                //add an edge from the main method to this method
                                cg.addEdge(new Edge(mainTPA.method, (Stmt) u, method));
                            }
                            else{

                            }
                        }
                    }
                }
            }
        }

        return cg;
    }
*/

    protected Pair<Set<Value>,Set<InvokeExpr>> getValuesWithType(SootMethod method, Type objectType){
        Set<Value> values = new HashSet<Value>();
        Set<InvokeExpr> invokeExprs = new HashSet<InvokeExpr>();

        if(method.hasActiveBody()){
            start:
            for(Unit u : method.getActiveBody().getUnits()){
                Value var;
                Value value;

                if(u instanceof IdentityStmt){
                    IdentityStmt identityStmt = (IdentityStmt) u;

                    var = identityStmt.getLeftOp();
                    value = identityStmt.getRightOp();
                }
                else if(u instanceof AssignStmt){

                    AssignStmt assignment = (AssignStmt) u;

                    var = assignment.getLeftOp();
                    value = assignment.getRightOp();
                    values.add(value);
                    values.add(var);
                    values.addAll(this.getRelevantValues(var));
                    values.addAll(this.getRelevantValues(value));
                }
                else if(u instanceof InvokeExpr){
                    invokeExprs.add((InvokeExpr) u);
                    values.addAll(this.getRelevantValues((InvokeExpr) u));
                    continue start;
                }
                else{
                    continue start;
                }

                if(value instanceof InvokeExpr){
                    values.add(var);
                    invokeExprs.add((InvokeExpr) value);
                    values.addAll(this.getRelevantValues((InvokeExpr) value));
                }
                if(var.getType().equals(objectType)
                        || value.getType().equals(objectType)
                        || values.contains(var)
                        || values.contains(value)){
                    values.add(value);
                    values.add(var);
                    values.addAll(this.getRelevantValues(var));
                    values.addAll(this.getRelevantValues(value));
                }
                //System.out.println(u.toString());
                //System.out.println(values);
            }
        }
        return new Pair<>(values, invokeExprs);
    }

    public Pair<Set<Value>,Set<InvokeExpr>> relevantPointers(SootMethod method, Pair<Set<Value>,Set<InvokeExpr>> pointerInvocations){
        Set<Value> values = pointerInvocations.first;
        Set<InvokeExpr> invocations = pointerInvocations.second;

        if(method.hasActiveBody()){
            start:
            for(Unit u : method.getActiveBody().getUnits()){
                Value var;
                Value value;

                if(u instanceof IdentityStmt){
                    IdentityStmt identityStmt = (IdentityStmt) u;

                    var = identityStmt.getLeftOp();
                    value = identityStmt.getRightOp();
                }
                else if(u instanceof AssignStmt){

                    AssignStmt assignment = (AssignStmt) u;

                    var = assignment.getLeftOp();
                    value = assignment.getRightOp();
                }
                else if(u instanceof InstanceInvokeExpr){
                    values.add(((InstanceInvokeExpr) u).getBase());
                    //we have to consider the args for methods that overloaded
                    //need to perhaps do a pre-analysis to check which are overloaded?
                    values.addAll(((InstanceInvokeExpr) u).getArgs());
                    continue start;
                }
                else{
                    continue start;
                }

                if(values.contains(var)
                        || values.contains(value)){
                    values.add(value);
                    values.add(var);
                    values.addAll(this.getRelevantValues(var));
                    values.addAll(this.getRelevantValues(value));
                }
            }
        }
        return new Pair<Set<Value>,Set<InvokeExpr>>(values, invocations);
    }

    public Set<Value> getRelevantValues(Value v){
        Set<Value> bases = new HashSet<Value>();
        if(v instanceof JInstanceFieldRef){
            Value base = ((JInstanceFieldRef) v).getBase();
            bases.add(base);
            bases.addAll(getRelevantValues(base));
        }
        else if(v instanceof InstanceInvokeExpr){
            InstanceInvokeExpr iie = (InstanceInvokeExpr) v;
            bases.add(iie.getBase());
            bases.addAll(iie.getArgs());
        }
        else if(v instanceof StaticInvokeExpr){
            StaticInvokeExpr iie = (StaticInvokeExpr) v;
            bases.addAll(iie.getArgs());
        }

        return bases;
    }

    protected TargetedPointerAnalysis pointerAnalysis(SootMethod method, Type objectType) {
        if(!method.hasActiveBody()){
            try {
                method.retrieveActiveBody();
                if (!method.hasActiveBody()) {
                    return null;
                }
            }catch (Exception e){
                return null;
            }
        }
        TrapUnitGraph cfg = new TrapUnitGraph(method.getActiveBody());

        //The first two pointer analyses can just be done as iterations over all edges
        //CorrectTypePointerAnalysis ctpa = new CorrectTypePointerAnalysis(cfg, method, Scene.v().getType("java.lang.Object"));

        Pair<Set<Value>,Set<InvokeExpr>> valueInvocationsPair = this.getValuesWithType(method, objectType);
        Pair<Set<Value>,Set<InvokeExpr>> newValueInvocationsPair = valueInvocationsPair;
        //System.out.println(valueInvocationsPair.first);
        do{
            valueInvocationsPair = new Pair<Set<Value>,Set<InvokeExpr>>(new HashSet<Value>(newValueInvocationsPair.first), new HashSet<InvokeExpr>(newValueInvocationsPair.second));
            //	RelevantPointerAnalysis rpa = new RelevantPointerAnalysis(cfg, method, values, new HashSet<SootMethod>());
            //System.out.println(valueInvocationsPair.first);
            newValueInvocationsPair = this.relevantPointers(method, valueInvocationsPair);

        }while(!valueInvocationsPair.equals(newValueInvocationsPair));
        //SimplePointerAnalysis spa = new SimplePointerAnalysis(cfg, stuff, Scene.v().getType("java.lang.Object"));

        //System.out.println(valueInvocationsPair.first);
        allValue.addAll(valueInvocationsPair.first);
        TargetedPointerAnalysis tpa = new TargetedPointerAnalysis(cfg, method, valueInvocationsPair.first);
        tpa.doAnalysis();


        dumpResult(tpa, method);
        //System.out.println(pointerResult);
        pointerResult.removeIf(s -> s.size() <= 1);
        return tpa;
    }


    public synchronized void dumpResult(TargetedPointerAnalysis tpa, SootMethod method){
        Iterator<Unit> unitIterator = method.getActiveBody().getUnits().iterator();

        System.out.println("Method: " + method.getName());
        while(unitIterator.hasNext()){
            Unit u = unitIterator.next();
            //System.out.println("processing stmt: "+u.toString());
            for(Pointer p : tpa.getFlowBefore(u).localAssignedTo.keySet()){
                for(Pointer q : tpa.getFallFlowAfter(u).localAssignedTo.keySet()){
                    if(p.equals(q)){continue;}
                    if(p.valueName.contains("$stack")||q.valueName.contains("$stack")){continue;}
                    if(tpa.mustAlias(p, (Stmt)u, q, (Stmt)u)){
                        int tmpFlag = 0;
                        for(Set<String> res : pointerResult){
                            if(res.contains(p.valueName)){
                                res.add(q.valueName);
                                tmpFlag = 1;
                                break;
                            }
                            else if(res.contains(q.valueName)){
                                res.add(p.valueName);
                                tmpFlag = 1;
                                break;
                            }
                        }
                        if(tmpFlag == 0){
                            Set<String> setForPointer = new HashSet<>();
                            setForPointer.add(p.valueName);
                            setForPointer.add(q.valueName);
                            pointerResult.add(setForPointer);
                        }

                    }
                    else if(tpa.mayAlias(p, (Stmt)u, q, (Stmt)u)){
                        int tmpFlag = 0;
                        for(Set<String> res : pointerResult){
                            if(res.contains(p.valueName)){
                                res.add(q.valueName);
                                tmpFlag = 1;
                                break;
                            }
                            else if(res.contains(q.valueName)){
                                res.add(p.valueName);
                                tmpFlag = 1;
                                break;
                            }
                        }
                        if(tmpFlag == 0){
                            //System.out.println("[INFO] "+p.toString() + " may alias with " + q.toString());
                            //System.out.println("[INFO] Add " +p.toString() + " and "+q.toString() +" to New Set");
                            Set<String> setForPointer = new HashSet<>();
                            setForPointer.add(p.valueName);
                            setForPointer.add(q.valueName);
                            pointerResult.add(setForPointer);
                        }
                    }
                }
            }
            //System.out.println("FlowBefore: " + tpa.getFlowBefore(u));
            //System.out.println("Statement: " + u);
            //System.out.println("FallFlow: " + tpa.getFallFlowAfter(u));
            //System.out.println("BranchFlow: " + tpa.getBranchFlowAfter(u));
            //System.out.println("--------------------");
        }
    }
}
