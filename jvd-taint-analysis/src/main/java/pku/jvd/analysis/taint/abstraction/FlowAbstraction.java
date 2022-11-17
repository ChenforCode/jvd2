package pku.jvd.analysis.taint.abstraction;

import boomerang.scene.Val;
import soot.*;
import soot.jimple.StaticFieldRef;
import soot.jimple.internal.JInstanceFieldRef;

import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

/**
 * Class containing the information to be aggregated during the analysis
 */
public class FlowAbstraction {

    //这个变量的来源即，i1 = i2 + i3，i1的来源就是这个表达式
    private Unit source;
    //表示i1这个变量
    private Value local;
    private String sinkName;
    private StaticFieldRef staticField;
    private boolean StaticModified;

    public String getFuncName() {
        return funcName;
    }

    public void setFuncName(String funcName) {
        this.funcName = funcName;
    }

    private String funcName;
    private String sourceName;
    private String locationName;//在哪一个函数里面，例如在main函数里面
    private SootField field;
    //是否是函数参数
    private boolean isArg;
    //函数参数的索引
    private int argIndex;
    private int sourceIndex;
    private FlowAbstraction parents;
    public int getDestIndex() {
        return destIndex;
    }
    public void setDestIndex(int destindex){this.destIndex = destindex;}
    private int destIndex;
    private boolean isRetval = false;//这个被污染值是否返回
    private boolean isArray = false;//这个被污染的值是不是数组
    private boolean isSink = false;//这个是以前设置的，暂时没有用上
    private boolean isSource = false;
    private boolean isTaintedByArgs;
    private boolean isTaintedByStatic;
    private boolean isThis;//被this语句确定为代表本类
    private boolean isThisTainted = true;//一条this链条（this以及相关变量）被完全污染,默认为true
    private boolean isTainted;//一条accesspath被完全污染
    private boolean isStatic;//是static
    private boolean isFullyTainted;//数组被完全污染的情况
    private boolean isTaintedByMember = false;//污染值被 this.a 污染
    private boolean isTaintedBySource = false;//污染值被source污染
    private boolean isTaintedByAccessPath = false;//污染涉及域敏感
    private boolean isClassMember = false;//为a.a这种
    private boolean isTaintedByClassMember = false;//如果被this.a这种污染
    private boolean isSinkTaintedByClassMember = false;//处理sink(a.a)的情况，之前无法检测

    private List<Integer> taintedArgsList = new ArrayList<>();//被污染参数表
    private List<Value> taintedIndexList = new ArrayList<>();//如果是数组，记录被污染的下标
    private List<SootField> taintedFieldList = new ArrayList<>();//针对域敏感，记录被污染的成员

    public FlowAbstraction(Unit source, String sinkName, boolean isSink) {
        this.source = source;
        this.sinkName = sinkName;
        this.isSink = isSink;
    }

    public FlowAbstraction(Unit source, String sourceName) {
        this.source = source;
        this.sourceName = sourceName;
    }

    public FlowAbstraction(Unit source, String funcName, int destIndex) {
        this.source = source;
        this.funcName = funcName;
        this.destIndex = destIndex;
    }

    public FlowAbstraction(Unit source, Value local, SootField field) {
        this.source = source;
        this.local = local;
        this.field = field;
    }
//    public FlowAbstraction(Unit source, Value local, SootField field) {
//        this.source = source;
//        this.local =  local;
//        this.field = field;
//    }
    public FlowAbstraction(Unit source, Value local, boolean isRetval, int argIndex) {
        this.source = source;
        this.local = local;
        this.isRetval = isRetval;
        this.argIndex = argIndex;
    }

    public FlowAbstraction(Local local,
                           boolean isArg,
                           int argIndex) {
        this.local = local;
        this.isArg = isArg;
        this.argIndex = argIndex;
    }

    public void setParents(FlowAbstraction flowAbstraction) {
        this.parents = flowAbstraction;
    }
    public FlowAbstraction getParents() {
        return parents;
    }
    public Unit getSource() {
        return source;
    }

    public Value getLocal() {
        return local;
    }

    public void setLocal(Value local) {
        this.local = local;
    }
    public void setIsSource(boolean isSource) {
        this.isSource = isSource;
    }
    public void setTaintedByAccessPath(boolean isTaintedByAccessPath) {
        this.isTaintedByAccessPath = isTaintedByAccessPath;
    }
    public String getLocationName() {
        return locationName;
    }
    public String getSourceName() {
        return sourceName;
    }
    public void setLocationName(String locationName) {
        this.locationName = locationName;
    }

    public boolean isArg() {
        return isArg;
    }
    public boolean isSource() {
        return isSource;
    }
    public boolean isTaintedByAccessPath() {
        return isTaintedByAccessPath;
    }
    public void setArg(boolean arg) {
        isArg = arg;
    }

    public int getArgIndex() {
        return argIndex;
    }
    public SootField getfield() {
        return field;
    }
    public void setArgIndex(int argIndex) {
        this.argIndex = argIndex;
    }

    public boolean isRetval() {
        return isRetval;
    }

    public void setRetval(boolean retval) {
        isRetval = retval;
    }
    public void setSourceIndex (int index) {
        sourceIndex = index;
    }
    public int getSourceIndex() {
        return sourceIndex;
    }
    public boolean isSink() {
        return isSink;
    }

    public void setSink(boolean sink) {
        isSink = sink;
    }

    public boolean isTaintedByArgs() {
        return isTaintedByArgs;
    }
    public boolean isFullyTainted () {
        return  isFullyTainted;
    }
    public boolean isTaintedByMember() {
        return isTaintedByMember;
    }

    public boolean isTaintedByClassMember() {
        return isTaintedByClassMember;
    }

    public boolean isSinkTaintedByClassMember() {
        return isSinkTaintedByClassMember;
    }

    public boolean isTaintedBySource() {
        return isTaintedBySource;
    }

    public boolean isClassMember() {
        return isClassMember;
    }

    public boolean isTaintedByStatic() { return isTaintedByStatic;}
    public boolean isStaticModified() { return StaticModified;}

    public boolean isThis() {
        return  isThis;
    }
    public boolean isStatic() {
        return  isStatic;
    }
    public void setTaintedByArgs(boolean taintedByArgs) {
        isTaintedByArgs = taintedByArgs;
    }
    public void setIsFullyTainted(boolean FullyTainted) {
        isFullyTainted = FullyTainted;
    }
    public void setIsClassMember(boolean ClassMember) {
        isClassMember = ClassMember;
    }
    public void setIsThis(boolean This) {
        isThis = This;
    }
    public void setIsStatic(boolean Static) {
        isStatic = Static;
    }
    public void setField(SootField field){this.field = field;}
    public void setIsStaticTaint(boolean b) { this.isTaintedByStatic = b;}
    public void setStaticModified(boolean b) {this.StaticModified = b;}
    public boolean getIsTainted(){return isTainted;}
    public void setIsTainted(boolean Tainted) {
        this.isTainted = Tainted;
    }
    public boolean isThisTainted() {
        return isThisTainted;
    }

    public void setisThisTainted(boolean thisTainted) {
        isThisTainted = thisTainted;
    }

    public void setTaintedByMember(boolean taintedByMember) {
        isTaintedByMember = taintedByMember;
    }

    public void setTaintedByClassMember(boolean taintedByClassMember) {
        isTaintedByClassMember = taintedByClassMember;
    }

    public void setTaintedBySource(boolean taintedBySource) {
        isTaintedBySource = taintedBySource;
    }

    public List<Integer> getTaintedArgsList() {
        return taintedArgsList;
    }


    public List<Value> getTaintedIndexList() {
        return taintedIndexList;
    }
    public List<SootField> getTaintedFieldList() {
        return taintedFieldList;
    }

    public StaticFieldRef getStaticField() {
        return staticField;
    }

    public void setTaintedArgsList(List<Integer> taintedArgsList) {
        this.taintedArgsList = taintedArgsList;
    }

    public void setisArray(boolean isArray) {
        this.isArray = isArray;
    }

    public void setTaintedIndexList(List<Value> taintedIndexList) {
        this.taintedIndexList = taintedIndexList;
    }
    public void setTaintedFieldList(List<SootField> taintedFieldList) {
        this.taintedFieldList = taintedFieldList;
    }
    public void setStatic(Value staticfield) {
        this.staticField = (StaticFieldRef) staticfield;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((local == null) ? 0 : local.hashCode());
        result = prime * result + ((field == null) ? 0 : field.hashCode());
        return result;
    }

//    @Override
//    public boolean equals(Object obj) {
//        if (this == obj)
//            return true;
//        if (obj == null || !(obj instanceof FlowAbstraction))
//            return false;
//        FlowAbstraction other = (FlowAbstraction) obj;
//        if (local == null) {
//            if (other.local != null)
//                return false;
//        } else if (!local.equals(other.local))
//            return false;
//        if (field == null) {
//            if (other.field != null)
//                return false;
//        } else if (!field.equals(other.field))
//            return false;
//        return true;
//    }

    @Override
    public String toString() {
        if (local != null)
            return "LOCAL " + local;
        if (field != null)
            return "FIELD " + field;
        return "";
    }


    public FlowAbstraction deriveWithNewSource(Unit newSource) {
        return new FlowAbstraction(newSource, local, field);
    }



}
