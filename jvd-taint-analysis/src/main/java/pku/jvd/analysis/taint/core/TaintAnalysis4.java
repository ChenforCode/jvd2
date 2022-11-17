package pku.jvd.analysis.taint.core;

//import pku.jvd.analysis.pointer.PtrTransformer;

import boomerang.scene.StaticFieldVal;
import boomerang.scene.Val;
import org.springframework.aop.scope.ScopedProxyUtils;
import pku.jvd.analysis.taint.core.pointerAnalysisTransformer;
import pku.jvd.analysis.taint.abstraction.EndpointConstant;
import pku.jvd.analysis.taint.abstraction.FlowAbstraction;
import soot.*;
import soot.dava.toolkits.base.AST.transformations.LoopStrengthener;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.jimple.parser.node.TInstanceof;
import soot.jimple.toolkits.annotation.logic.Loop;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.LoopNestTree;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

class FieldRef {
    SootField field = null;
    Unit source;
    boolean sourceSetted = false;
    Set<Value> Locals = new HashSet<>();
}

public class TaintAnalysis4 extends ForwardFlowAnalysis<Unit, Set<FlowAbstraction>> {
    Map<FlowAbstraction, Set<FlowAbstraction>> argsTaintMap;//例如{arg1: <a, b, c>, arg2: <a, c, e>}
    Map<FlowAbstraction, List<FlowAbstraction>> argsChain; //{arg1: [sink, retVal], arg2:[sink]}
    Map<FlowAbstraction, Stack<FieldRef>> FieldMap;//{l1:[{a : $stack1,$stack5}{b : $stack2}{c : $stack3}]} 代表l1.a.b.c
    List<String> ClearedStaticList;
    List<String> ModifiedStaticList;
    private Body body;
    private SootMethod method;
    private boolean isInitArgs;
    List<Local> bodyArgs;
    public Map<String, Map<FlowAbstraction, List<FlowAbstraction>>> taintMap;//最终结果{funcA: argsChainMap_funcA}
    public Map<String, Set<FlowAbstraction>> sourceMap;
    public Set<FlowAbstraction> sourceSet = new HashSet<>();
    private int index = 0;
    private EndpointConstant endpointConstant;
    private Map<Stmt, List<Stmt>> loopMaps;
    private Set<Stmt> beAnalyzed = new HashSet<>();
    private Set<Set<Value>> aliasSetRes = new HashSet<>();


    public TaintAnalysis4(UnitGraph g,
                          Map<String, Map<FlowAbstraction, List<FlowAbstraction>>> m,
                          Map<String, Set<FlowAbstraction>> sourceMap,
                          Body body,
                          SootMethod sootMethod,
                          EndpointConstant endpointConstant,
                          Map<Stmt, List<Stmt>> loopMaps,
                          Set<Stmt> beAnalyzed) {
        super(g);
        argsTaintMap = new HashMap<>();
        argsChain = new HashMap<>();
        ClearedStaticList = new ArrayList<>();
        ModifiedStaticList = new ArrayList<>();
        this.sourceMap = sourceMap;
        this.taintMap = m;
        this.body = body;
        this.endpointConstant = endpointConstant;
        this.method = sootMethod;
        bodyArgs = sootMethod.getActiveBody().getParameterLocals();
        this.loopMaps = loopMaps;
        this.beAnalyzed = beAnalyzed;
        this.doAnalyis();
    }


    @Override
    protected Set<FlowAbstraction> newInitialFlow() {
        return new HashSet<FlowAbstraction>();
    }

    @Override
    protected Set<FlowAbstraction> entryInitialFlow() {
        return new HashSet<FlowAbstraction>();
    }

    protected void merge(Set<FlowAbstraction> in1, Set<FlowAbstraction> in2, Set<FlowAbstraction> out) {
        out.addAll(in1);
        out.addAll(in2);
    }

    protected void copy(Set<FlowAbstraction> source, Set<FlowAbstraction> dest) {
        dest.clear();
        dest.addAll(source);
    }

    public void doAnalyis() {

        super.doAnalysis();
        removeRedundantChain();
    }

    /**
     * @Param []
     * @Return void
     * @Description 对方法分析的数据结构argsTaintMap和argsChain初始化
     **/
    public void init() {
        if (!isInitArgs) {
            List<Local> body_args = method.getActiveBody().getParameterLocals();
            for (int i = 0; i < body_args.size(); i++) {
                Local local = body_args.get(i);
                FlowAbstraction flowAbstraction = new FlowAbstraction(local, true, i);
                flowAbstraction.setLocationName(method.getSignature());
                flowAbstraction.setIsFullyTainted(true);
                Set<FlowAbstraction> argTaintSet = new HashSet<>();//一个参数有一个set 里面存的是被这个参数影响的变量
                argTaintSet.add(flowAbstraction);
                argsTaintMap.put(flowAbstraction, argTaintSet);//先用当前的参数来初始化map  即最开始状态一个参数的set里只有他自己
                argsChain.put(flowAbstraction, new LinkedList<>());
            }
            FieldMap = new HashMap<>();
            isInitArgs = true;
        }
        if (!pointerAnalysisTransformer.aliasSetRes.isEmpty()) {
            aliasSetRes = pointerAnalysisTransformer.aliasSetRes;
        } else if (!pointerAnalysisTransformerFast.aliasSetRes.isEmpty()) {
            aliasSetRes = pointerAnalysisTransformerFast.aliasSetRes;
        }
    }

    /**
     * @Param []
     * @Return void
     * @Description 删除冗余的链条。例如空链
     **/
    public void removeRedundantChain() {
        Map<FlowAbstraction, List<FlowAbstraction>> tempChain = new HashMap<>();
        for (Map.Entry<FlowAbstraction, List<FlowAbstraction>> curchain : argsChain.entrySet()) {
            tempChain.put(curchain.getKey(), curchain.getValue());
        }
        //删除空链
        for (Map.Entry<FlowAbstraction, List<FlowAbstraction>> curchain : tempChain.entrySet()) {
            FlowAbstraction arg = curchain.getKey();
            List<FlowAbstraction> chainList = curchain.getValue();
            if (chainList.size() == 0) {
                argsChain.remove(arg);
            }
        }
    }

    /**
     * @Param [s, d]
     * @Return void
     * @Description 获取jimple指派的this变量并存入Map中
     **/
    private void manageIdentityStmt(JIdentityStmt s, Unit d) {
        if (s.getRightOpBox().getValue() instanceof ThisRef) {
            Set<FlowAbstraction> argTaintSet = new HashSet<>();
            Value leftOp = s.getLeftOpBox().getValue();
            FlowAbstraction leftTaint = new FlowAbstraction(d, leftOp, null);
            leftTaint.setIsThis(true);
            leftTaint.setArgIndex(-1);
            leftTaint.setLocationName(method.getSignature());
            argTaintSet.add(leftTaint);
            argsTaintMap.put(leftTaint, argTaintSet);
            argsChain.put(leftTaint, new LinkedList<>());
        }

    }

    /**
     * @Param [rightOp, leftOp, d]
     * @Return void
     * @Description 处理普通的赋值语句。例如 a = b.
     * 如果b在某个参数的污点集合里，将a也要加入这个参数的集合中
     * 处理域敏感，将信息存到FieldMap中
     * 2022.7.2 新增加对staticField处理
     **/
    public void manageLocalAssignment(Value rightOp, Value leftOp, Unit d) {
        //遍历每个参数的污点集合
        Value rightOpIndex = null;
        SootField rightField = null;
        if (rightOp instanceof JInstanceFieldRef) {//处理域敏感
            rightField = ((JInstanceFieldRef) rightOp).getField();//得到域名称
            boolean isIn = false;//避免存在重复
            boolean isCreated = false;//避免存在重复
            Stack<FieldRef> copyStack = new Stack<>();
            FlowAbstraction RefField = new FlowAbstraction(d, ((JInstanceFieldRef) rightOp).getBase(), null);
            if (FieldMap != null) {
                for (FlowAbstraction key : FieldMap.keySet()) {//遍历
                    Stack<FieldRef> tempStack = FieldMap.get(key);//获取对应的stack

                    if (((JInstanceFieldRef) rightOp).getBase() == key.getLocal()
                            && ((JInstanceFieldRef) rightOp).getField() == key.getfield()) {//如果l.a.b.c已经存在，此时引用l.a，则FieldRef中增加local
                        tempStack.get(0).Locals.add(leftOp);
                        isIn = true;
                    } else if (((JInstanceFieldRef) rightOp).getBase() == key.getLocal()
                            && rightField != key.getfield()) {
                        //如果l.a.b.c已经存在，此时引用l.b，则在FieldMap中新增加一条path
                        isIn = false;
                        RefField.setLocal(((JInstanceFieldRef) rightOp).getBase());
                        RefField.setField(rightField);
                    } else {//如果l.a.b.c已经存在，此时引用l.a.b.c，或者l.a.b.c.d,或者l.a.c
                        for (int i = 0; i < tempStack.size(); i++) {//遍历stack
                            FieldRef fieldRef = tempStack.get(i);
                            if (fieldRef.Locals.contains(((JInstanceFieldRef) rightOp).getBase())) {
                                //引用l.a.b.c或者l.a.b.c.d
                                if ((i + 1) == tempStack.size()) {//如果引用l.a.b.c.d,则在栈顶添加元素
                                    FieldRef fieldref = new FieldRef();
                                    fieldref.field = rightField;
                                    fieldref.Locals.add(leftOp);
                                    tempStack.add(fieldref);
                                    isIn = true;
                                    break;
                                } else {
                                    //引用l.a.b.c,则FieldRef中增加local
                                    //如果引用l.a.c，则在FieldMap中新增加一条path
                                    if ((i + 1) <= tempStack.size() && tempStack.get(i + 1).field == rightField) {
                                        //引用l.a.b.c,则FieldRef中增加local
                                        tempStack.get(i + 1).Locals.add(leftOp);
                                        isIn = true;
                                        break;
                                    } else {
                                        //如果引用l.a.c，则在FieldMap中新增加一条path
                                        if (!isCreated && !isIn) {//避免重复
                                            isIn = false;
                                            for (int j = 0; j <= i; j++) {//标记需要拷贝的位置
                                                FieldRef field = new FieldRef();
                                                field.sourceSetted = false;
                                                field.source = null;
                                                field.field = tempStack.get(j).field;
                                                for (Value local : tempStack.get(j).Locals)
                                                    field.Locals.add(local);
                                                copyStack.add(field);
                                            }
                                            RefField.setLocal(key.getLocal());
                                            RefField.setField(key.getfield());
                                            isCreated = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (!isIn) {//在FieldMap中新增加一条path
                    FieldRef fieldRef = new FieldRef();
                    fieldRef.field = rightField;
                    fieldRef.Locals.add(leftOp);
                    if (copyStack.size() == 0) {
                        RefField.setField(rightField);
                    } else {
                        RefField.setField(copyStack.get(0).field);
                    }
                    copyStack.add(fieldRef);
                    FieldMap.put(RefField, copyStack);
                }
            }
            rightOp = ((JInstanceFieldRef) rightOp).getBase();//得到变量名称
        } else if (leftOp instanceof JInstanceFieldRef) {//处理域敏感
            boolean rightTaint = false;
            for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                Set<FlowAbstraction> curTaintSet = taint.getValue();//拿到某个参数的污点集合
                for (FlowAbstraction flowAbstraction : curTaintSet) {
                    if (flowAbstraction.getLocal() == rightOp) { //如果右值出现在了集合中，将左值也加入这个集合
                        rightTaint = true;
                    }
                }
            }
            if (!rightTaint) {
                //清除左值原本的污点状态
                clearTaint(leftOp, d, rightOp);
            }
            SootField leftField = ((JInstanceFieldRef) leftOp).getField();//得到域名称
            boolean isIn = false;
            Stack<FieldRef> copyStack = new Stack<>();
            FlowAbstraction RefField = new FlowAbstraction(d, ((JInstanceFieldRef) leftOp).getBase(), null);
            if (FieldMap != null) {
                for (FlowAbstraction key : FieldMap.keySet()) {//遍历
                    Stack<FieldRef> tempStack = FieldMap.get(key);//获取对应的stack
                    if (((JInstanceFieldRef) leftOp).getBase() == key.getLocal()
                            && ((JInstanceFieldRef) leftOp).getField() == key.getfield()) {//如果l.a.b.c已经存在，此时引用l.a，则FieldRef中增加local
                        tempStack.get(0).Locals.add(rightOp);
                        isIn = true;
                    } else if (((JInstanceFieldRef) leftOp).getBase() == key.getLocal()
                            && leftField != key.getfield()) {
                        //如果l.a.b.c已经存在，此时引用l.b，则在FieldMap中新增加一条path
                        isIn = false;
                        RefField.setLocal(((JInstanceFieldRef) leftOp).getBase());
                        RefField.setField(leftField);
                    } else {//如果l.a.b.c已经存在，此时引用l.a.b.c，或者l.a.b.c.d,或者l.a.c
                        for (int i = 0; i < tempStack.size(); i++) {//遍历stack
                            FieldRef fieldRef = tempStack.get(i);
                            if (fieldRef.Locals.contains(((JInstanceFieldRef) leftOp).getBase())) {
                                //引用l.a.b.c或者l.a.b.c.d
                                if ((i + 1) == tempStack.size()) {//如果引用l.a.b.c.d,则在栈顶添加元素
                                    FieldRef fieldref = new FieldRef();
                                    fieldref.field = leftField;
                                    //fieldref.Locals.add((Local) leftOp);
                                    tempStack.add(fieldref);
                                    isIn = true;
                                    break;
                                } else {
                                    //引用l.a.b.c,则FieldRef中增加local
                                    //如果引用l.a.c，则在FieldMap中新增加一条path
                                    if ((i + 1) <= tempStack.size() && tempStack.get(i + 1).field == leftField) {
                                        //引用l.a.b.c,则FieldRef中增加local
                                        //tempStack.get(i + 1).Locals.add((Local) leftOp);
                                        isIn = true;
                                        break;
                                    } else {
                                        //如果引用l.a.c，则在FieldMap中新增加一条path
                                        isIn = false;
                                        for (int j = 0; j <= i; j++) {//标记需要拷贝的位置
                                            FieldRef field = new FieldRef();
                                            field.sourceSetted = false;
                                            field.source = null;
                                            field.field = tempStack.get(j).field;
                                            for (Value local : tempStack.get(j).Locals)
                                                field.Locals.add(local);
                                            copyStack.add(field);
                                        }
                                        RefField.setLocal(key.getLocal());
                                        RefField.setField(key.getfield());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if (!isIn) {//在FieldMap中新增加一条path
                    FieldRef fieldRef = new FieldRef();
                    fieldRef.field = leftField;
                    // fieldRef.Locals.add((Local) ((JInstanceFieldRef) leftOp).getBase());
                    copyStack.add(fieldRef);
                    RefField.setField(copyStack.get(0).field);
                    FieldMap.put(RefField, copyStack);
                }
            }
        } else if (rightOp instanceof JArrayRef) {
            //清除左值原本的污点状态
            clearTaint(leftOp, d, rightOp);
            rightOpIndex = ((JArrayRef) rightOp).getIndex();
            rightOp = ((JArrayRef) rightOp).getBaseBox().getValue();
        } else if (rightOp instanceof JCastExpr) {
            //清除左值原本的污点状态
            clearTaint(leftOp, d, rightOp);
            rightOp = ((JCastExpr) rightOp).getOp();
        } else if (rightOp instanceof StaticFieldRef) {//记录这个变量被static影响（可能被污染也可能不被污染）
            clearTaint(leftOp, d, rightOp);
            Set<FlowAbstraction> argTaintSet = new HashSet<>();
            FlowAbstraction leftTaint = new FlowAbstraction(d, leftOp, null);
            leftTaint.setArgIndex(-1);
            if (!ClearedStaticList.contains(rightOp.toString()))
                leftTaint.setIsStaticTaint(true);
            if (ModifiedStaticList.contains(rightOp.toString()))
                leftTaint.setStaticModified(true);
            leftTaint.setStatic(rightOp);
            leftTaint.setLocationName(method.getSignature());
            //leftTaint.setFuncName(method.getSignature());
            argTaintSet.add(leftTaint);
            argsTaintMap.put(leftTaint, argTaintSet);
            argsChain.put(leftTaint, new LinkedList<>());
        } else {
            //清除左值原本的污点状态
            clearTaint(leftOp, d, rightOp);
        }

        //遍历每个参数的污点集合
        for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
            Set<FlowAbstraction> curTaintSet = taint.getValue();//拿到某个参数的污点集合
            Set<FlowAbstraction> temp = new HashSet<>();
            FlowAbstraction curArg = taint.getKey();
            for (FlowAbstraction flowAbstraction : curTaintSet) {
                temp.add(flowAbstraction);//深拷贝
            }
            for (FlowAbstraction flowAbstraction : temp) {
                if (flowAbstraction.getLocal().toString().equals(rightOp.toString())) { //如果右值出现在了集合中，将左值也加入这个集合
                    if (!flowAbstraction.isArg() && !flowAbstraction.isThis() && rightField != null
                            && !flowAbstraction.getTaintedFieldList().contains(rightField)
                            && flowAbstraction.getTaintedFieldList().size() != 0) {
                        break;
                    }
                    FlowAbstraction leftTaint = null;
                    if (leftOp instanceof JInstanceFieldRef) {
                        leftTaint = new FlowAbstraction(d, ((JInstanceFieldRef) leftOp).getBase(), null);
                        List<SootField> TaintedFieldList = leftTaint.getTaintedFieldList();
                        TaintedFieldList.add(((JInstanceFieldRef) leftOp).getField());
                        leftTaint.setTaintedFieldList(TaintedFieldList);
                        leftTaint.setLocationName(method.getSignature());
                    } else if (leftOp instanceof JArrayRef) {
                        leftTaint = new FlowAbstraction(d, ((JArrayRef) leftOp).getBaseBox().getValue(), null);
                        leftTaint.setLocationName(method.getSignature());
                        List<Value> TaintedIndexList = leftTaint.getTaintedIndexList();
                        TaintedIndexList.add(((JArrayRef) leftOp).getIndex());
                        leftTaint.setTaintedIndexList(TaintedIndexList);
                    } else if (leftOp instanceof ThisRef) {//如果左值恰好是一个this 记录一个 arg->this的去向
                        List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                        leftTaint = new FlowAbstraction(d, leftOp, null);
                        leftTaint.setLocationName(method.getSignature());
                        if (!argsChainList.contains(leftTaint)) {
                            argsChainList.add(leftTaint);
                        }
                        argsChain.put(curArg, argsChainList);
                    } else if (leftOp instanceof StaticFieldRef) {//如果左值是一个StaticField 记录一个污染流入staticfield的去向
                        List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                        leftTaint = new FlowAbstraction(d, leftOp, null);
                        leftTaint.setLocationName(method.getSignature());
                        leftTaint.setDestIndex(-1);
                        leftTaint.setIsStatic(true);
                        String a = leftOp.toString();
                        if (ClearedStaticList.contains(leftOp.toString()))
                            ClearedStaticList.remove(leftOp.toString());
                        if (!ModifiedStaticList.contains(leftOp.toString()))
                            ModifiedStaticList.add(leftOp.toString());
                        if (!argsChainList.contains(leftTaint)) {
                            argsChainList.add(leftTaint);
                        }
                        argsChain.put(curArg, argsChainList);
                    } else {//处理数组情况，精确到索引
                        if (rightOpIndex != null) {//如果右值是数组
                            List<Value> taintIndexlist = flowAbstraction.getTaintedIndexList();
                            if (taintIndexlist.contains(rightOpIndex) ||
                                    flowAbstraction.isFullyTainted()) {
                                //只有在数组被完全污染或者指定索引被污染，才会污染左值
                                leftTaint = new FlowAbstraction(d, leftOp, null);
                                leftTaint.setLocationName(method.getSignature());
                            }
                        } else {
                            leftTaint = new FlowAbstraction(d, leftOp, null);
                            //leftTaint.setIsFullyTainted(true);
                            leftTaint.setLocationName(method.getSignature());
                        }
                    }
                    if (leftTaint != null) {//处理域敏感
                        boolean isTainted = false;//是否整条链条都被污染
                        if (FieldMap != null) {
                            for (FlowAbstraction key : FieldMap.keySet()) {//遍历，处理域敏感
                                Stack<FieldRef> tempStack = FieldMap.get(key);
                                for (FieldRef field : tempStack) {
                                    if (field.Locals.contains(leftTaint.getLocal()) || key.getLocal() == leftTaint.getLocal()) {//这一条链条被污染
                                        isTainted = true;
                                        break;
                                    }
                                }
                                if (isTainted) {//如果这一条链条被污染,则标记所有这一链条中元素为被污染
                                    for (FieldRef field : tempStack) {//设定污染source
                                        if (!field.sourceSetted) {
                                            field.sourceSetted = true;
                                            field.source = flowAbstraction.getSource();
                                        }
                                    }
                                    Unit source = tempStack.get(0).source;//使这一条链污染的source
                                    // if(source == taint.getKey().getSource()) {
                                    for (int i = 0; i < tempStack.size(); i++) {//如果没有重复项目，添加到curTaintSet里面，如果有，就更新taintFieldSet
                                        FieldRef field = tempStack.get(i);
                                        for (Value local : field.Locals) {
                                            FlowAbstraction localTaint = new FlowAbstraction(d, local, null);
                                            boolean isInTaintSet = false;//是否存在重复项目
                                            for (FlowAbstraction fabs : curTaintSet) {//避免重复项目
                                                if (localTaint.getLocal() == fabs.getLocal()) {//存在重复项目
                                                    List<SootField> TaintedFieldList = new ArrayList<>();
                                                    for (SootField TaintedField : fabs.getTaintedFieldList())
                                                        TaintedFieldList.add(TaintedField);
                                                    if ((i + 1) != tempStack.size()) {
                                                        if (!TaintedFieldList.contains(tempStack.get(i + 1).field))
                                                            TaintedFieldList.add(tempStack.get(i + 1).field);
                                                    }
                                                    fabs.setTaintedFieldList(TaintedFieldList);
                                                    isInTaintSet = true;
                                                }
                                            }
                                            if (!isInTaintSet) {//不存在重复项目,则新建一个加入curTaintSet
                                                for (FlowAbstraction fabs : curTaintSet) {//避免重复项目
                                                    if (field.Locals.contains(fabs.getLocal()) && field.Locals.contains(localTaint.getLocal())) {//存在重复项目
                                                        List<SootField> TaintedFieldList = new ArrayList<>();
                                                        for (SootField TaintedField : fabs.getTaintedFieldList())
                                                            TaintedFieldList.add(TaintedField);
                                                        localTaint.setTaintedFieldList(TaintedFieldList);
                                                    }
                                                }
                                                List<SootField> TaintedFieldList = new ArrayList<>();
                                                for (SootField TaintedField : localTaint.getTaintedFieldList())
                                                    TaintedFieldList.add(TaintedField);
                                                if ((i + 1) != tempStack.size()) {
                                                    if (!TaintedFieldList.contains(tempStack.get(i + 1).field))
                                                        TaintedFieldList.add(tempStack.get(i + 1).field);
                                                }
                                                localTaint.setTaintedFieldList(TaintedFieldList);
                                                if (source == taint.getKey().getSource()) { //保证是确定的source污染的
                                                    localTaint.setTaintedByAccessPath(true);
                                                    curTaintSet.add(localTaint);
                                                }
                                            }
                                        }
                                    }
                                    boolean isInTaintSet = false;//同时标记变量l.a.b中l为被污染，避免重复
                                    for (FlowAbstraction fabs : curTaintSet) {//避免重复项目
                                        if (key.getLocal() == fabs.getLocal()) {//存在重复项目
                                            isInTaintSet = true;
                                            List<SootField> TaintedFieldList = new ArrayList<>();
                                            for (SootField TaintedField : key.getTaintedFieldList())
                                                TaintedFieldList.add(TaintedField);
                                            if (!TaintedFieldList.contains(tempStack.get(0).field))
                                                TaintedFieldList.add(tempStack.get(0).field);
                                            //TaintedFieldList.add(key.getfield());
                                            key.setTaintedFieldList(TaintedFieldList);
                                            fabs.setTaintedFieldList(TaintedFieldList);
                                        }
                                    }
                                    if (!isInTaintSet) {//在argsTaintMap创建一个新元素
                                        List<SootField> TaintedFieldList = new ArrayList<>();
                                        for (SootField TaintedField : key.getTaintedFieldList())
                                            TaintedFieldList.add(TaintedField);
                                        if (!TaintedFieldList.contains(tempStack.get(0).field))
                                            TaintedFieldList.add(tempStack.get(0).field);
                                        //TaintedFieldList.add(key.getfield());
                                        key.setField(tempStack.get(0).field);
                                        key.setTaintedFieldList(TaintedFieldList);
                                        key.setTaintedByAccessPath(true);
                                        curTaintSet.add(key);
                                    }
                                }
                            }
                        }
                        if (!isTainted) {
                            leftTaint.setTaintedByAccessPath(true);
                            curTaintSet.add(leftTaint);
                        }
                    }
                    argsTaintMap.put(curArg, curTaintSet);
                }
            }
        }
    }

    /**
     * @Param [leftOp, d]
     * @Return void
     * @Description 如果右值是一个常数，类似于a = 3的形式，域敏感情况下类似l.a.b.c = 1
     * 看a是否在某个参数的污点集合中。如果在，则从集合中移除
     * 2月11日新增域敏感：看a是否在某个参数的污点集合中。如果在，并且涉及域敏感，
     * 则从集合中移除accesspath中的每一个元素
     **/
    public void clearTaint(Value leftOp, Unit d, Value rightOp) {
        Value leftOpIndex = null;
        if (leftOp instanceof JInstanceFieldRef) {
            leftOp = ((JInstanceFieldRef) leftOp).getBase();
        } else if (leftOp instanceof JArrayRef) {
            leftOpIndex = ((JArrayRef) leftOp).getIndex();
            leftOp = ((JArrayRef) leftOp).getBaseBox().getValue();
        } else if (leftOp instanceof StaticFieldRef) {
            if (!ClearedStaticList.contains(leftOp.toString()))
                ClearedStaticList.add(leftOp.toString());
        }
        //遍历每个参数的污点集合
        for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
            Set<FlowAbstraction> curTaintSet = taint.getValue();//拿到某个参数的污点集合
            Set<FlowAbstraction> temp = new HashSet<>();
            for (FlowAbstraction flowAbstraction : curTaintSet) {
                temp.add(flowAbstraction);//深拷贝
            }
            for (FlowAbstraction flowAbstraction : temp) {
                if (flowAbstraction.getLocal() == leftOp) { //如果左值出现在了集合中，将左值从集合中清除
                    if (leftOpIndex != null) {//处理l[1] = 0，保证不会清除l[0]的污染
                        List<Value> taintedIndexList = flowAbstraction.getTaintedIndexList();
                        taintedIndexList.remove(leftOpIndex);
                        if (taintedIndexList.size() == 0) {
                            FlowAbstraction flowAbstraction1 = new FlowAbstraction(d, leftOp, null);
                            flowAbstraction1.setLocationName(method.getSignature());
                            curTaintSet.remove(flowAbstraction1);
                        } else {
                            flowAbstraction.setTaintedIndexList(taintedIndexList);
                        }
                    } else if (flowAbstraction.isTaintedByAccessPath()) {//涉及域敏感
                        for (FlowAbstraction key : FieldMap.keySet()) {//遍历每一个accesspath，处理域敏感
                            Stack<FieldRef> tempStack = FieldMap.get(key);
                            boolean isInTaintSet = false;//是否存在于本accesspath中
                            for (int i = 0; i < tempStack.size() && isInTaintSet == false; i++) {//遍历stack
                                FieldRef field = tempStack.get(i);
                                for (Value local : field.Locals) {
                                    if (local == flowAbstraction.getLocal()) {//存在,清除此链条的污染
                                        isInTaintSet = true;//需要清除这一条链的污染
                                        break;
                                    }
                                }
                            }
                            if (flowAbstraction.getLocal() == key.getLocal() && flowAbstraction.getfield() == key.getfield())
                                isInTaintSet = true;//需要清除这一条链的污染
                            if (isInTaintSet) {
                                Set<FlowAbstraction> temp1 = new HashSet<>();
                                for (FlowAbstraction flowAbstraction2 : curTaintSet) {
                                    temp1.add(flowAbstraction2);//深拷贝
                                }
                                for (FlowAbstraction flowAbstraction1 : temp1) {//清除被污染域
                                    for (int i = 0; i < tempStack.size(); i++) {//遍历stack
                                        FieldRef field = tempStack.get(i);
                                        for (Value local : field.Locals) {//遍历local
                                            if (flowAbstraction1.getLocal() == local) {
                                                field.sourceSetted = false;
                                                field.source = null;
                                                if ((i + 1) != tempStack.size()) {//对于非栈顶元素
                                                    List<SootField> TaintedFieldList = new ArrayList<>();
                                                    for (SootField TaintedField : flowAbstraction1.getTaintedFieldList()) {
                                                        if (TaintedField != tempStack.get(i + 1).field)
                                                            TaintedFieldList.add(TaintedField);
                                                    }
                                                    flowAbstraction1.setTaintedFieldList(TaintedFieldList);
                                                    if (flowAbstraction1.getTaintedFieldList().size() == 0) {
                                                        curTaintSet.remove(flowAbstraction1);
                                                    }
                                                } else {//对于栈顶元素
                                                    curTaintSet.remove(flowAbstraction1);
                                                }
                                            }
                                        }
                                    }
                                    if (flowAbstraction1.getLocal() == key.getLocal() && flowAbstraction.getfield() == key.getfield()) {
                                        //移除冗余项目
                                        List<SootField> TaintedFieldList = new ArrayList<>();
                                        for (SootField TaintedField : flowAbstraction1.getTaintedFieldList()) {
                                            if (TaintedField != tempStack.get(0).field)
                                                TaintedFieldList.add(TaintedField);
                                        }
                                        flowAbstraction1.setTaintedFieldList(TaintedFieldList);
                                        if (flowAbstraction1.getTaintedFieldList().size() == 0) {
                                            curTaintSet.remove(flowAbstraction1);//如果被污染元素涉及域敏感，但所有被污染field污染都已被清空，则移除笨元素
                                        }
                                    }
                                }

                            }
                        }
                    }//处理域敏感结束
                   else if(flowAbstraction.isThis()) {
                        //处理成员变量污染清除
                        flowAbstraction.setisThisTainted(false);
                    }
                    else {
                        FlowAbstraction flowAbstraction1 = new FlowAbstraction(d, leftOp, null);
                        flowAbstraction1.setLocationName(method.getSignature());
                        curTaintSet.remove(flowAbstraction1);
                    }
                    argsTaintMap.put(taint.getKey(), curTaintSet);
                }
            }
        }
    }

    /**
     * @Param [rightOp, leftOp, d]
     * @Return void
     * @Description 处理二元运算。右值任意一个在污点集合中，则将左值加入污点集合
     **/
    public void manageBinOpStmt(Value rightOp, Value leftOp, Unit d) {
        clearTaint(leftOp, d, rightOp);
        BinopExpr rightOpBinary = (BinopExpr) rightOp;
        Value rightOp1 = rightOpBinary.getOp1();
        Value rightOp2 = rightOpBinary.getOp2();

//        if (rightOp1 instanceof JInstanceFieldRef) {
//            rightOp1 = ((JInstanceFieldRef) rightOp).getBase();
//        } else if (rightOp1 instanceof JArrayRef) {
//            rightOp1 = ((JArrayRef) rightOp).getBaseBox().getValue();
//        }
//        if (rightOp2 instanceof JInstanceFieldRef) {
//            rightOp2 = ((JInstanceFieldRef) rightOp).getBase();
//        } else if (rightOp2 instanceof JArrayRef) {
//            rightOp2 = ((JArrayRef) rightOp).getBaseBox().getValue();
//        }

        //根据指针分析结果对op1和op2进行拓展
        Set<Value> rightValues = new HashSet<>();
        rightValues.add(rightOp1);
        rightValues.add(rightOp2);

        for (Set<Value> sv : aliasSetRes) {
            if (sv.contains(rightOp1) || sv.contains(rightOp2)) {
                rightValues.addAll(sv);
                break;
            }
        }
        for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
            Set<FlowAbstraction> curTaintSet = taint.getValue();
            Set<FlowAbstraction> temp = new HashSet<>();
            FlowAbstraction curArg = taint.getKey();
            for (FlowAbstraction flowAbstraction : curTaintSet) {
                temp.add(flowAbstraction);//深拷贝
            }
            for (FlowAbstraction flowAbstraction : temp) {
                //如果右值任意一个在污点集合中，将左值加入污点中
                if (rightValues.contains((Value) flowAbstraction.getLocal())) {
                    FlowAbstraction leftTaint;
                    if (leftOp instanceof JInstanceFieldRef) {
                        leftTaint = new FlowAbstraction(d, ((JInstanceFieldRef) leftOp).getBase(), null);
                        leftTaint.setLocationName(method.getSignature());
                    } else if (leftOp instanceof JArrayRef) {
                        leftTaint = new FlowAbstraction(d, ((JArrayRef) leftOp).getBaseBox().getValue(), null);
                        leftTaint.setLocationName(method.getSignature());
                    } else if (leftOp instanceof ThisRef) {//如果左值恰好是一个this 记录一个 arg->this的去向
                        List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                        leftTaint = new FlowAbstraction(d, leftOp, null);
                        leftTaint.setLocationName(method.getSignature());
                        if (!argsChainList.contains(leftTaint)) {
                            argsChainList.add(leftTaint);
                        }
                        argsChain.put(curArg, argsChainList);
                    } else {
                        leftTaint = new FlowAbstraction(d, leftOp, null);
                        leftTaint.setLocationName(method.getSignature());
                    }
                    curTaintSet.add(leftTaint);
                    argsTaintMap.put(curArg, curTaintSet);
                }
            }
        }
    }

    /**
     * @Param [jInvokeStmt, d]
     * @Return void
     * @Description 处理非赋值型函数调用。
     * 如果是sink方法，直接看sink的参数是否包含在某个参数的污点集合中，如果在，则加入chainList，找到了一条链
     * 如果是普通的函数调用，首先判断实参是否在参数的污点集合里，如果在，记录下当前这个实参是第几号位，并进行下一步
     * 拿到callee的分析结果，看callee分析结果的list中是否有一条从第i号位参数传出去的一条链，
     * 如果有，说明arg能走到callee并从callee继续传出去。这条链通了。记录下arg->callee
     **/
    public void manageFunc(JInvokeStmt jInvokeStmt, Unit d) {
        InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
        SootMethod calleeMethod = invokeExpr.getMethod();
        Value invokeValue = null;
        if (invokeExpr instanceof InstanceInvokeExpr)
            invokeValue = ((InstanceInvokeExpr) invokeExpr).getBase();
        List<Value> calleeParam = invokeExpr.getArgs();//拿到callee的所有参数
        //先遍历calleeParam，如果里面有域的引用，先把它转成base，后面再去和taintMap匹配
        List<Value> calleeParamBase = calleeParam.stream().map(e -> {
            if (e instanceof JInstanceFieldRef) {
                return ((JInstanceFieldRef) e).getBase();
            } else if (e instanceof JArrayRef) {
                return ((JArrayRef) e).getBaseBox().getValue();
            }
            return e;
        }).collect(Collectors.toList());
        if (calleeMethod.isJavaLibraryMethod() || endpointConstant.isSink(calleeMethod.getSignature())) {
            if (endpointConstant.isSink(calleeMethod.getSignature())) { //todo  之后改成getSignature
                for (Value value : calleeParamBase) {//遍历sink的参数
                    for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {//遍历args的集合
                        Set<FlowAbstraction> curTaintSet = taint.getValue();//当前args影响的变量
                        FlowAbstraction curArg = taint.getKey();
                        for (FlowAbstraction flowAbstraction : curTaintSet) {
                            //根据指针分析结果对污点集合进行拓展，判断是否继续传播
                            boolean flag = false;
                            for (Set<Value> sv : aliasSetRes) {
                                if (sv.contains(value)) {
                                    flag = true;
                                    break;
                                }
                            }
                            if (value == flowAbstraction.getLocal() || flag) {//如果sink的参数是args影响的变量，链通
                                List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                                FlowAbstraction sinkTaint = new FlowAbstraction(d, calleeMethod.getSignature(), true);
                                sinkTaint.setLocationName(method.getSignature());
//                                if (!argsChainList.contains(sinkTaint)) {//避免加入重复的去向
//                                    argsChainList.add(sinkTaint);//sink点
//                                }
                                boolean flag1 = false;
                                for (FlowAbstraction f : argsChainList) {
                                    if (f.getLocationName() == sinkTaint.getLocationName() &&
                                            f.getSource() == sinkTaint.getSource()) {
                                        flag1 = true;
                                    }
                                }
                                if (!flag1) {//避免加入重复的去向
                                    argsChainList.add(sinkTaint);//sink点
                                }
                                argsChain.put(curArg, argsChainList);
                            }
                        }
                    }
                }
                //sink的调用者是否是污点
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {//遍历args的集合
                    Set<FlowAbstraction> curTaintSet = taint.getValue();//当前args影响的变量
                    FlowAbstraction curArg = taint.getKey();
                    for (FlowAbstraction flowAbstraction : curTaintSet) {
                        if (invokeValue == flowAbstraction.getLocal()) {//如果sink的参数是args影响的变量，链通
                            List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                            FlowAbstraction sinkTaint = new FlowAbstraction(d, calleeMethod.getSignature(), true);
                            sinkTaint.setLocationName(method.getSignature());
                            if (!argsChainList.contains(sinkTaint)) {//避免加入重复的去向
                                argsChainList.add(sinkTaint);//sink点
                            }
                            argsChain.put(curArg, argsChainList);
                        }
                    }
                }
            }

            //参数影响调用者，如果调用者本来就在污点集合中，不管它。如果不在，看参数是否在，在就将调用者加入污点
            if (EndpointConstant.isArgToInvoke(calleeMethod.getSignature()) ||
                    EndpointConstant.isInitMethod(calleeMethod.getName())) {
                boolean isInvokeValInTaint = false;
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                    Set<FlowAbstraction> curTaintSet = taint.getValue();//当前args影响的变量
                    FlowAbstraction curArg = taint.getKey();
                    Set<FlowAbstraction> temp = new HashSet<>();
                    for (FlowAbstraction flowAbstraction : curTaintSet) {
                        temp.add(flowAbstraction);
                        if (invokeValue == flowAbstraction.getLocal()) {
                            isInvokeValInTaint = true;
                        }
                    }
                    if (!isInvokeValInTaint) { //如果invokeValue不在污点中
                        for (Value param : calleeParamBase) {
                            for (FlowAbstraction flowAbstraction : temp) {
                                //如果参数在污点集合里
                                if (flowAbstraction.getLocal() == param) {//参数在污点中，将invokeValue加入污点
                                    int flag = 0;
                                    //将invokeValue的别名变量也加入污点
                                    for(Set<Value> sv:aliasSetRes){
                                        if(sv.contains(invokeValue)){
                                            flag = 1;
                                            for(Value v:sv){
                                                FlowAbstraction invokeTaint = new FlowAbstraction(d, v, null);
                                                invokeTaint.setLocationName(method.getSignature());
                                                curTaintSet.add(invokeTaint);
                                                argsTaintMap.put(curArg, curTaintSet);
                                            }
                                        }
                                    }
                                    if(flag == 0){
                                        FlowAbstraction invokeTaint = new FlowAbstraction(d, invokeValue, null);
                                        invokeTaint.setLocationName(method.getSignature());
                                        curTaintSet.add(invokeTaint);
                                        argsTaintMap.put(curArg, curTaintSet);
                                    }
                                }

                            }
                        }

                    }
                }

            }
        } else {
            //看sink的参数在不在args的集合里
            //如果是普通的函数调用
            if (taintMap.get(calleeMethod.getSignature()) == null) {
                return;
            }
            Map<FlowAbstraction, List<FlowAbstraction>> calleeTaintMap = taintMap.get(calleeMethod.getSignature());
            //callee(a, b)
            //1. 遍历callee的所有实参
            for (int i = 0; i < calleeParamBase.size(); i++) {
                //2. 判断实参是不是在argsTaintMap里
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                    Set<FlowAbstraction> taintValue = taint.getValue();
                    for (FlowAbstraction flowAbstraction : taintValue) {
                        if (flowAbstraction.getLocal() == calleeParamBase.get(i)) {//第i个实参是被arg的污点集合影响的
                            FlowAbstraction curArg = taint.getKey();
                            //3、判断callee的分析结果里是不是有这个i
                            //遍历calleeTaint的分析结果那个list
                            for (Map.Entry<FlowAbstraction, List<FlowAbstraction>> calleeTaintRes : calleeTaintMap.entrySet()) {
                                FlowAbstraction calleeTaint = calleeTaintRes.getKey();
                                if (calleeTaint.getArgIndex() == i) { //能传通，加入一个从arg->callee的链
                                    List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                                    FlowAbstraction newNode = new FlowAbstraction(d, calleeMethod.getSignature(), i);
                                    newNode.setLocationName(method.getSignature());
                                    if (!argsChainList.contains(newNode)) { //避免加入重复的去向
                                        argsChainList.add(newNode);
                                    }
                                    argsChain.put(curArg, argsChainList);
                                }
                            }
                        }
                    }
                }
            }
            //对分析结果遍历
            for (Map.Entry<FlowAbstraction, List<FlowAbstraction>> calleeTaintRes : calleeTaintMap.entrySet()) {
                FlowAbstraction key = calleeTaintRes.getKey();
                //如果分析结果中存在一条链key是this，并且这个this会传递污染（isThistainted）看invokeValue是不是污点，是的话传通
                if (key.isThis() && key.isThisTainted()) {
                    for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                        Set<FlowAbstraction> taintValueSet = taint.getValue();
                        FlowAbstraction taintKey = taint.getKey();
                        for (FlowAbstraction flowAbstraction : taintValueSet) {
                            if (invokeValue == flowAbstraction.getLocal()) {
                                List<FlowAbstraction> list = argsChain.get(taintKey);
                                FlowAbstraction node = new FlowAbstraction(d, calleeMethod.getSignature(), -1);
                                node.setLocationName(method.getSignature());
                                if (!list.contains(node)) {
                                    list.add(node);
                                }
                                argsChain.put(taintKey, list);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @Param [jAssignStmt, leftOp, d]
     * @Return void
     * @Description 处理赋值型函数调用。区别于非赋值型，需要再增加判断从callee走通的那条链里的节点是否有retVal
     * 如果有，则把左值加入arg的污点集合中（这个arg是走到实参，然后走进callee最后走到retVal的那个参数）
     **/
    public void manageFuncAsmt(JAssignStmt jAssignStmt, Value leftOp, Value rightOp, Unit d) {
//        if (leftOp instanceof JInstanceFieldRef) {
//            leftOp = ((JInstanceFieldRef) leftOp).getBase();
//        } else if (leftOp instanceof JArrayRef) {
//            leftOp = ((JArrayRef) leftOp).getBaseBox().getValue();
//        }
        clearTaint(leftOp, d, rightOp);
        InvokeExpr invokeExpr = jAssignStmt.getInvokeExpr();
        SootMethod calleeMethod = invokeExpr.getMethod();
        Value invokeValue = null;
        if (invokeExpr instanceof InstanceInvokeExpr) {// InstanceInvokeExpr包含specialinvoke、jvirtualinvoke等
            invokeValue = ((InstanceInvokeExpr) invokeExpr).getBaseBox().getValue();//获得例如：a.fun()里面的a这个元素
        }
        List<Value> calleeParam = invokeExpr.getArgs();//拿到callee的所有参数
        //先遍历calleeParam，如果里面有域的引用，先把它转成base，后面再去和taintMap匹配
        List<Value> calleeParamBase = calleeParam.stream().map(e -> {
            if (e instanceof JInstanceFieldRef) {
                return ((JInstanceFieldRef) e).getBase();
            } else if (e instanceof JArrayRef) {
                return ((JArrayRef) e).getBaseBox().getValue();
            }
            return e;
        }).collect(Collectors.toList());
        //如果被调用函数是一个包装好的source
        FlowAbstraction calleeIsSource = null;
        for (Map.Entry<String, Set<FlowAbstraction>> sourceTaint : sourceMap.entrySet()) {
            Set<FlowAbstraction> curSourceSet = sourceTaint.getValue();
            for (FlowAbstraction flowAbstraction : curSourceSet) {
                if (flowAbstraction.getSourceName().equals(calleeMethod.getSignature())) {
                    calleeIsSource = flowAbstraction;//把当前这个包装好的source拿出来
                }
            }
        }
        if (calleeMethod.isJavaLibraryMethod() ||
                endpointConstant.isSink(calleeMethod.getSignature()) ||
                endpointConstant.isSource(calleeMethod.getSignature()) ||
                calleeIsSource != null) {
            if (endpointConstant.isSink(calleeMethod.getSignature())) {
                for (Value value : calleeParamBase) {//遍历sink的参数
                    for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {//遍历args的集合
                        Set<FlowAbstraction> curTaintSet = taint.getValue();//当前args影响的变量
                        FlowAbstraction curArg = taint.getKey();
                        for (FlowAbstraction flowAbstraction : curTaintSet) {
                            if (value == flowAbstraction.getLocal()) {//如果sink的参数是args影响的变量，链通
                                List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                                FlowAbstraction sinkTaint = new FlowAbstraction(d, calleeMethod.getSignature(), true);
                                sinkTaint.setLocationName(method.getSignature());
                                if (!argsChainList.contains(sinkTaint)) {//避免加入重复的去向
                                    argsChainList.add(sinkTaint);//sink点
                                }
                                argsChain.put(curArg, argsChainList);
                            }
                        }
                    }
                }
                //sink的调用者是否是污点
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {//遍历args的集合
                    Set<FlowAbstraction> curTaintSet = taint.getValue();//当前args影响的变量
                    FlowAbstraction curArg = taint.getKey();
                    for (FlowAbstraction flowAbstraction : curTaintSet) {
                        if(invokeValue == flowAbstraction.getLocal()) {//如果sink的参数是args影响的变量，链通
                            List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                            FlowAbstraction sinkTaint = new FlowAbstraction(d, calleeMethod.getSignature(), true);
                            sinkTaint.setLocationName(method.getSignature());
                            if (!argsChainList.contains(sinkTaint)) {//避免加入重复的去向
                                argsChainList.add(sinkTaint);//sink点
                            }
                            argsChain.put(curArg, argsChainList);
                        }
                    }
                }
            }

            if (endpointConstant.isSource(calleeMethod.getSignature()) || calleeIsSource != null) {
                FlowAbstraction source = new FlowAbstraction(d, calleeMethod.getSignature());
                if (calleeIsSource != null) {
                    source.setParents(calleeIsSource.getParents());
                }
                source.setLocationName(method.getSignature());
                source.setIsSource(true);
                source.setSourceIndex(index);
                index++;
                sourceSet.add(source);
                sourceMap.put(method.getSignature(), sourceSet);//记录到sourceMap里，第二轮搜索的时候从map里取source开始搜

                Set<FlowAbstraction> argTaintSet = new HashSet<>();
                FlowAbstraction leftTaint;
                if (leftOp instanceof JInstanceFieldRef) {
                    leftTaint = new FlowAbstraction(d, ((JInstanceFieldRef) leftOp).getBase(), null);
                    leftTaint.setLocationName(method.getSignature());
                    leftTaint.setIsFullyTainted(true);
                } else if (leftOp instanceof JArrayRef) {
                    leftTaint = new FlowAbstraction(d, ((JArrayRef) leftOp).getBaseBox().getValue(), null);
                    leftTaint.setLocationName(method.getSignature());
                    List<Value> TaintedIndexList = leftTaint.getTaintedIndexList();
                    TaintedIndexList.add(((JArrayRef) leftOp).getIndex());
                    leftTaint.setTaintedIndexList(TaintedIndexList);
                } else {
                    leftTaint = new FlowAbstraction(d, leftOp, null);
                    leftTaint.setLocationName(method.getSignature());
                    leftTaint.setIsFullyTainted(true);
                }
                argTaintSet.add(leftTaint);//source也同样像参数一样开始传播
                argsTaintMap.put(source, argTaintSet);//先用当前的参数来初始化map  即最开始状态一个参数的set里只有他自己
                argsChain.put(source, new LinkedList<>());
            }
            if (EndpointConstant.isToStringMethod(calleeMethod.getName()) ||
                    EndpointConstant.isInvokeToLeft(calleeMethod.getSignature())) {
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                    Set<FlowAbstraction> taintValue = taint.getValue();
                    Set<FlowAbstraction> temp = new HashSet<>();
                    for (FlowAbstraction flowAbstraction : taintValue) {
                        temp.add(flowAbstraction);//深拷贝
                    }

                    for (FlowAbstraction flowAbstraction : temp) {
                        if (invokeValue == flowAbstraction.getLocal()) {
                            FlowAbstraction curArg = taint.getKey();
                            FlowAbstraction leftTaint;
                            if (leftOp instanceof JInstanceFieldRef) {
                                leftTaint = new FlowAbstraction(d, ((JInstanceFieldRef) leftOp).getBase(), null);
                                leftTaint.setIsFullyTainted(true);
                                leftTaint.setLocationName(method.getSignature());
                            } else if (leftOp instanceof JArrayRef) {
                                leftTaint = new FlowAbstraction(d, ((JArrayRef) leftOp).getBaseBox().getValue(), null);
                                leftTaint.setLocationName(method.getSignature());
                                List<Value> TaintedIndexList = leftTaint.getTaintedIndexList();
                                TaintedIndexList.add(((JArrayRef) leftOp).getIndex());
                                leftTaint.setTaintedIndexList(TaintedIndexList);
                            } else {
                                leftTaint = new FlowAbstraction(d, leftOp, null);
                                leftTaint.setIsFullyTainted(true);
                                leftTaint.setLocationName(method.getSignature());
                            }
                            taintValue.add(leftTaint);
                            argsTaintMap.put(curArg, taintValue);
                        }
                    }
                }
            }
            if (EndpointConstant.isValueOfMethod(calleeMethod.getName()) ||
                    EndpointConstant.isArgToLeft(calleeMethod.getSignature())) {
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                    Set<FlowAbstraction> taintValue = taint.getValue();
                    Set<FlowAbstraction> temp = new HashSet<>();
                    for (FlowAbstraction flowAbstraction : taintValue) {
                        temp.add(flowAbstraction);//深拷贝
                    }
                    for (Value param : calleeParamBase) {
                        for (FlowAbstraction flowAbstraction : temp) {
                            if (param == flowAbstraction.getLocal()) {
                                FlowAbstraction curArg = taint.getKey();
                                FlowAbstraction leftTaint;
                                if (leftOp instanceof JInstanceFieldRef) {
                                    leftTaint = new FlowAbstraction(d, ((JInstanceFieldRef) leftOp).getBase(), null);
                                    leftTaint.setIsFullyTainted(true);
                                    leftTaint.setLocationName(method.getSignature());
                                } else if (leftOp instanceof JArrayRef) {
                                    leftTaint = new FlowAbstraction(d, ((JArrayRef) leftOp).getBaseBox().getValue(), null);
                                    leftTaint.setLocationName(method.getSignature());
                                    List<Value> TaintedIndexList = leftTaint.getTaintedIndexList();
                                    TaintedIndexList.add(((JArrayRef) leftOp).getIndex());
                                    leftTaint.setTaintedIndexList(TaintedIndexList);
                                } else {
                                    leftTaint = new FlowAbstraction(d, leftOp, null);
                                    leftTaint.setIsFullyTainted(true);
                                    leftTaint.setLocationName(method.getSignature());
                                }
                                taintValue.add(leftTaint);
                                argsTaintMap.put(curArg, taintValue);
                            }
                        }
                    }

                }
            }
            if (EndpointConstant.isInvokeArgToLeft(calleeMethod.getName())) {
                //如果invokeVal在污点集合中，直接将左值加入污点集合。如果不在，且参数在污点集合，则将左值加入污点集合
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                    Set<FlowAbstraction> taintValue = taint.getValue();
                    Set<FlowAbstraction> temp = new HashSet<>();
                    FlowAbstraction curArg = taint.getKey();
                    for (FlowAbstraction flowAbstraction : taintValue) {
                        temp.add(flowAbstraction);//深拷贝
                    }
                    for (FlowAbstraction flowAbstraction : temp) {
                        //左值有可能被加两次
                        if (invokeValue == flowAbstraction.getLocal()) {
                            FlowAbstraction leftTaint;
                            leftTaint = new FlowAbstraction(d, leftOp, null);
                            leftTaint.setLocationName(method.getSignature());
                            taintValue.add(leftTaint);
                            argsTaintMap.put(curArg, taintValue);
                        }
                        for (Value param : calleeParamBase) {
                            //b或者c任意一个在污点中，将左值加入污点
                            if (param == flowAbstraction.getLocal()) {
                                FlowAbstraction leftTaint;
                                leftTaint = new FlowAbstraction(d, leftOp, null);
                                leftTaint.setLocationName(method.getSignature());
                                argsTaintMap.get(curArg).add(leftTaint);//现在的taintValue可能已经变了
                                argsTaintMap.put(curArg, taintValue);
                            }
                        }
                    }
                }
            }
        } else {
            if (taintMap.get(calleeMethod.getSignature()) == null) {
                return;
            }
            Map<FlowAbstraction, List<FlowAbstraction>> calleeTaintMap = taintMap.get(calleeMethod.getSignature());

            //下面再来考虑参数的情况
            //callee(a, b)
            //1. 遍历callee的所有实参
            for (int i = 0; i < calleeParamBase.size(); i++) {
                //2. 判断实参是不是在argsTaintMap里
                for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
                    Set<FlowAbstraction> taintValue = taint.getValue();
                    Set<FlowAbstraction> temp = new HashSet<>();//先保存下这个值，否则后面将返回值加入污点集合会导致在循环内部对循环条件做修改
                    for (FlowAbstraction flowAbstraction : taintValue) {
                        temp.add(flowAbstraction);//深拷贝
                    }
                    for (FlowAbstraction flowAbstraction : temp) {
                        if (flowAbstraction.getLocal() == calleeParamBase.get(i)) {//第i个参数在污点集合里
                            FlowAbstraction curArg = taint.getKey();//拿到当前这个参数（是指调用者里那个参数）
                            //3、判断callee的分析结果里是不是有这个i
                            //遍历calleeTaint的分析结果的key
                            for (Map.Entry<FlowAbstraction, List<FlowAbstraction>> calleeTaintRes : calleeTaintMap.entrySet()) {
                                FlowAbstraction calleeTaint = calleeTaintRes.getKey();
                                List<FlowAbstraction> calleeTaintList = calleeTaintRes.getValue();
                                if (calleeTaint.getArgIndex() == i) { //能传通，加入一个从arg->callee的链（这里只用考虑arg的index，不用考虑source）
                                    List<FlowAbstraction> argsChainList = argsChain.get(curArg);
                                    FlowAbstraction newNode = new FlowAbstraction(d, calleeMethod.getSignature(), i);
                                    newNode.setLocationName(method.getSignature());
                                    if (!argsChainList.contains(newNode)) { //避免加入重复的去向
                                        argsChainList.add(newNode);
                                        argsChain.put(curArg, argsChainList);
                                    }
                                    //还要看传通的这条链里有没有retVal，有就把左值加入到args的set里
                                    for (FlowAbstraction abstraction : calleeTaintList) {
                                        if (abstraction.isRetval()) {
                                            FlowAbstraction ret = new FlowAbstraction(d, leftOp, null);
                                            ret.setLocationName(method.getSignature());
                                            taintValue.add(ret);
                                            argsTaintMap.put(curArg, taintValue);
                                            if (abstraction.isThis()) {//如果这个返回值恰好是一个this 记录一个 arg->this的去向
                                                List<FlowAbstraction> list = argsChain.get(curArg);
                                                FlowAbstraction node = new FlowAbstraction(d, leftOp, null);
                                                node.setLocationName(method.getSignature());
                                                if (!list.contains(node)) {
                                                    list.add(node);
                                                }
                                                argsChain.put(curArg, list);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @Param [returnStmt, d]
     * @Return void
     * @Description 处理retVal.拿到ret的值，如果这个值在某个参数arg的污点集合里，那么加上一条从arg->retval的链
     **/
    public void manageRet(ReturnStmt returnStmt, Unit d) {
        Value retValue = returnStmt.getOp();
//        if (retValue instanceof StaticFieldRef) {
//            return;
//        }
//        if (retValue instanceof JInstanceFieldRef) {
//            retValue = ((JInstanceFieldRef) retValue).getBase();
//        } else if (retValue instanceof JArrayRef) {
//            retValue = ((JArrayRef) retValue).getBaseBox().getValue();
//        }
        for (Map.Entry<FlowAbstraction, Set<FlowAbstraction>> taint : argsTaintMap.entrySet()) {
            Set<FlowAbstraction> taintValueSet = taint.getValue();
            FlowAbstraction curArg = taint.getKey();
            for (FlowAbstraction flowAbstraction : taintValueSet) {
                if (flowAbstraction.getLocal() == retValue) {
                    List<FlowAbstraction> argsChainList = argsChain.get(taint.getKey());
                    FlowAbstraction newNode = new FlowAbstraction(d, retValue, true, curArg.getArgIndex());
                    newNode.setLocationName(method.getSignature());
                    if (!argsChainList.contains(newNode)) { //避免加入重复的去向
                        argsChainList.add(newNode);
                    }
                    argsChain.put(curArg, argsChainList);
                    //如果返回值是一个source影响的变量
                    if (curArg.isSource()) {
                        FlowAbstraction source = new FlowAbstraction(d, method.getSignature());
                        //todo 标记这个包装的source所在的位置。应该是谁用到了就是什么
//                        source.setLocationName(method.getSignature());
                        source.setIsSource(true);
                        source.setParents(curArg);
                        source.setSourceIndex(index);
                        index++;
                        sourceSet.add(source);
                        sourceMap.put(method.getSignature(), sourceSet);
                    }
                }
            }
        }
    }

    public void handleStmts(Stmt s, Unit d) {
        if (s instanceof JInvokeStmt) {//非赋值调用函数
            manageFunc((JInvokeStmt) s, d);
        } else if (s instanceof JAssignStmt) {//赋值语句
            JAssignStmt as = (JAssignStmt) s;
            Value rightOp = as.getRightOp();
            Value leftOp = as.getLeftOp();
            if (rightOp instanceof InvokeExpr) {
                manageFuncAsmt(as, leftOp, rightOp, d);
            } else if (rightOp instanceof JimpleLocal
                    || leftOp instanceof StaticFieldRef
                    || rightOp instanceof StaticFieldRef) {
                manageLocalAssignment(rightOp, leftOp, d);
                for (Set<Value> sv : aliasSetRes) {
                    if (sv.contains(rightOp)) {
                        for (Value v : sv) {
                            if (leftOp != v && !v.toString().contains("$stack")) {
                                manageLocalAssignment(rightOp, v, d);
                            }
                        }
                        break;
                    }
                }
            } else if (rightOp instanceof JInstanceFieldRef) {
                manageLocalAssignment(rightOp, leftOp, d);
            } else if (rightOp instanceof JArrayRef) {
                manageLocalAssignment(rightOp, leftOp, d);
            } else if (rightOp instanceof JCastExpr) {
                manageLocalAssignment(rightOp, leftOp, d);
            } else if (rightOp instanceof Constant) {
                clearTaint(leftOp, d, rightOp);
            } else if (rightOp instanceof BinopExpr) {//二项式，a+b
                manageBinOpStmt(rightOp, leftOp, d);
                for (Set<Value> sv : aliasSetRes) {
                    if (sv.contains(leftOp)) {
                        for (Value v : sv) {
                            if (leftOp != v && !v.toString().contains("$stack")) {
                                manageLocalAssignment(rightOp, v, d);
                            }
                        }
                        break;
                    }
                }
            } else if (rightOp instanceof NewExpr ||
                    rightOp instanceof JNewArrayExpr) {
                clearTaint(leftOp, d, rightOp);
            }
        } else if (s instanceof JIdentityStmt) {//处理this语句
            manageIdentityStmt((JIdentityStmt) s, d);
        } else if (s instanceof ReturnStmt) {//处理return 语句
            //todo  s instanceof JReturnVoidStmt
            manageRet((ReturnStmt) s, d);
        }
    }

    @Override
    protected void flowThrough(Set<FlowAbstraction> taintsIn, Unit d, Set<FlowAbstraction> taintsOut) {
        init();//初始化
        Stmt s = (Stmt) d;//获取语句
        if (loopMaps.containsKey(s)) {
            List<Stmt> loopStmts = loopMaps.get(s);
            for (Stmt loopStmt : loopStmts) {
                handleStmts(loopStmt, (Unit) loopStmt);
                beAnalyzed.add(loopStmt);
            }
        } else {
            if (!beAnalyzed.contains(s)) {
                handleStmts(s, d);
            }
        }
    }
}


