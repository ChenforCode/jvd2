package pku.jvd.analysis.taint.abstraction;

import java.util.ArrayList;
import java.util.List;

/**
 * @description sink & source
 */
public class EndpointConstant {
    public List<String> sinkMethod = new ArrayList<>();
    public List<String> sourceMethod = new ArrayList<>();
    public static List<String> argToInvoke = new ArrayList<>();
    public static List<String> toStringMethod = new ArrayList<>();
    public static List<String> invokeToLeft = new ArrayList<>();
    public static List<String> argToLeft = new ArrayList<>();
    public static List<String> invokeArgToLeft = new ArrayList<>();
    public static List<String> valueOfMethod = new ArrayList<>();
    public static List<String> initMethod = new ArrayList<>();

    static {
        argToInvoke.add("<java.util.Vector: void add(int,java.lang.Object)>");
//        argToInvoke.add("<java.sql.PreparedStatement: void setString(int,java.lang.String)>");
        argToInvoke.add("<java.util.LinkedList: void add(int,java.lang.Object)>");
        argToInvoke.add("<java.util.HashMap: java.lang.Object put(java.lang.Object,java.lang.Object)>");
        argToInvoke.add("<java.sql.Statement: void addBatch(java.lang.String)>");
        //stringBuffer
        argToInvoke.add("<java.lang.StringBuffer: void setCharAt(int,char)>");
        argToInvoke.add("<java.lang.StringBuilder: void setCharAt(int,char)>");
        argToInvoke.add("<java.io.ObjectOutput: void writeObject(java.lang.Object)>(java.lang.String)");
        initMethod.add("<init>");

        toStringMethod.add("toByteArray");
        toStringMethod.add("substring");
        toStringMethod.add("toString");
        toStringMethod.add("toHexString");
        toStringMethod.add("toBinaryString");
        toStringMethod.add("toOctalString");

        invokeToLeft.add("<java.util.HashMap: java.lang.Object get(java.lang.Object)>");
        invokeToLeft.add("<javax.servlet.http.Cookie: java.lang.String getValue()>");
        invokeToLeft.add("<java.lang.String: java.lang.String[] split(java.lang.String)>");
        invokeToLeft.add("<java.util.StringTokenizer: java.lang.String nextToken()>");
        invokeToLeft.add("<java.util.LinkedList: java.lang.Object remove(int)>");//todo  增加 map的remove方法
        invokeToLeft.add("<java.util.ArrayList: java.lang.Object remove(int)>");
        invokeToLeft.add("<java.util.Vector: java.lang.Object remove(int)>");
        invokeToLeft.add("<java.lang.String: char charAt(int)>");//string  stringBuffer
        invokeToLeft.add("<java.lang.StringBuffer: char charAt(int)>");
        invokeToLeft.add("<java.lang.StringBuilder: char charAt(int)>");
        invokeToLeft.add("<java.lang.String: byte[] getBytes(java.nio.charset.Charset)>");
        invokeToLeft.add("<java.lang.String: byte[] getBytes()>");
        invokeToLeft.add("<java.lang.String: byte[] getBytes(java.nio.charset.Charset)>");
        invokeToLeft.add("<java.lang.StringBuffer: void getChars(int,int,char[],int)>");
        invokeToLeft.add("<java.lang.StringBuilder: void getChars(int,int,char[],int)>");
        invokeToLeft.add("<java.lang.String: java.lang.String substring(int)>");
        invokeToLeft.add("<java.lang.String: java.lang.String substring(int,int)>");
        invokeToLeft.add("<java.lang.StringBuffer: java.lang.String substring(int)>");
        invokeToLeft.add("<java.lang.StringBuffer: java.lang.String substring(int,int)>");
        invokeToLeft.add("<java.lang.StringBuilder: java.lang.String substring(int)>");
        invokeToLeft.add("<java.lang.StringBuilder: java.lang.String substring(int,int)>");
        invokeToLeft.add("<java.lang.String: char[] toCharArray()>");
        invokeToLeft.add("<java.lang.String: java.lang.String toLowerCase(java.util.Locale)>");
        invokeToLeft.add("<java.lang.String: java.lang.String toLowerCase()>");
        invokeToLeft.add("<java.lang.String: java.lang.String toUpperCase(java.util.Locale)>");
        invokeToLeft.add("<java.lang.String: java.lang.String toUpperCase()>");
        invokeToLeft.add("<java.lang.String: java.lang.String trim()>");
        invokeToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer reverse()>");
        invokeToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder reverse()>");
        invokeToLeft.add("<java.lang.String: java.lang.CharSequence subSequence(int,int)>");
        invokeToLeft.add("<java.lang.StringBuffer: java.lang.CharSequence subSequence(int,int)>");
        invokeToLeft.add("<java.lang.StringBuilder: java.lang.CharSequence subSequence(int,int)>");
        invokeToLeft.add("<java.io.ObjectInputStream: java.lang.Object readObject()>()");

        valueOfMethod.add("valueOf");

        argToLeft.add("<java.lang.String: int lastIndexOf(int)>");
        argToLeft.add("<java.lang.String: java.lang.String format(java.lang.String,java.lang.Object[])>");
        argToLeft.add("<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String)>");

        invokeArgToLeft.add("append");
        invokeArgToLeft.add("replaceAll");
        invokeArgToLeft.add("replace");
        invokeArgToLeft.add("<java.lang.String: java.lang.String concat(java.lang.String)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,int)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,char)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,long)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,float)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,double)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,boolean)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,char[])>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,java.lang.Object)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,java.lang.String)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,java.lang.Object)>");
        invokeArgToLeft.add("<java.lang.StringBuffer: java.lang.StringBuffer insert(int,char[],int,int)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,int)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,char)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,long)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,float)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,double)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,boolean)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,char[])>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,java.lang.Object)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,java.lang.String)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,java.lang.Object)>");
        invokeArgToLeft.add("<java.lang.StringBuilder: java.lang.StringBuilder insert(int,char[],int,int)>");
    }

    public EndpointConstant() {
        //测试sink和source
        sinkMethod.add("<cn.chenforcode.Test: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.Test: int source()>");
        sinkMethod.add("<cn.chenforcode.doublePath: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.doublePath: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.doublePath: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.doublePath: int source()>");
        sinkMethod.add("<cn.chenforcode.longPath: void sink(cn.chenforcode.C_longPath)>");
        sinkMethod.add("<cn.chenforcode.longPath: void sink(cn.chenforcode.A_longPath)>");
        sinkMethod.add("<cn.chenforcode.longPath: void sink(cn.chenforcode.B_longPath)>");
        sinkMethod.add("<cn.chenforcode.longPath: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.longPath: int source()>");

        sourceMethod.add("<aliastest.aliasViaParameter: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.aliasViaParameter: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.branch: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.branch: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.cast: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.cast: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.interprocedualBranch: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.interprocedualBranch: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.interprocedualTest1: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.interprocedualTest1: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.simpleAssignment1: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.simpleAssignment1: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.simpleAssignment2: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.simpleAssignment2: void sink(aliastest.alias1)>");
        sourceMethod.add("<aliastest.wrappedAllocationSite: aliastest.alias1 source()>");
        sinkMethod.add("<aliastest.wrappedAllocationSite: void sink(aliastest.alias1)>");

        sinkMethod.add("<cn.chenforcode.ClearPath: void sink(cn.chenforcode.C_ClearPath)>");
        sinkMethod.add("<cn.chenforcode.ClearPath: void sink(cn.chenforcode.A_ClearPath)>");
        sinkMethod.add("<cn.chenforcode.ClearPath: void sink(cn.chenforcode.B_ClearPath)>");
        sinkMethod.add("<cn.chenforcode.ClearPath: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.ClearPath: int source()>");

        sinkMethod.add("<cn.chenforcode.ClearPath2: void sink(cn.chenforcode.C_ClearPath2)>");
        sinkMethod.add("<cn.chenforcode.ClearPath2: void sink(cn.chenforcode.A_ClearPath2)>");
        sinkMethod.add("<cn.chenforcode.ClearPath2: void sink(cn.chenforcode.B_ClearPath2)>");
        sinkMethod.add("<cn.chenforcode.ClearPath2: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.ClearPath2: int source()>");

        sinkMethod.add("<cn.chenforcode.shortPath: void sink(cn.chenforcode.C_shortPath)>");
        sinkMethod.add("<cn.chenforcode.shortPath: void sink(cn.chenforcode.A_shortPath)>");
        sinkMethod.add("<cn.chenforcode.shortPath: void sink(cn.chenforcode.B_shortPath)>");
        sinkMethod.add("<cn.chenforcode.shortPath: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.shortPath: cn.chenforcode.B_shortPath source()>");

        sinkMethod.add("<cn.chenforcode.doubleTaintPath: void sink(cn.chenforcode.C_doubleTaintPath)>");
        sinkMethod.add("<cn.chenforcode.doubleTaintPath: void sink(cn.chenforcode.A_doubleTaintPath)>");
        sinkMethod.add("<cn.chenforcode.doubleTaintPath: void sink(cn.chenforcode.B_doubleTaintPath)>");
        sinkMethod.add("<cn.chenforcode.doubleTaintPath: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.doubleTaintPath: int source()>");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase3: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase3: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase3: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase3: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase3: int source()>");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase4: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase4: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase4: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase4: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase4: int source()>");


        sinkMethod.add("<cn.chenforcode.SensetiveTestCase5: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase5: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase5: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase5: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase5: int source()>");


        sinkMethod.add("<cn.chenforcode.SensetiveTestCase6: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase6: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase6: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase6: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase6: int source()>");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase7: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase7: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase7: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase7: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase7: int source()>");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase8: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase8: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase8: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase8: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase8: cn.chenforcode.C source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase9: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase9: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase9: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase9: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase9: cn.chenforcode.C source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase10: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase10: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase10: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase10: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase10: cn.chenforcode.C source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase11: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase11: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase11: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase11: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase11: cn.chenforcode.B source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase12: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase12: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase12: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase12: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase12: cn.chenforcode.B source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase13: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase13: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase13: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase13: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase13: cn.chenforcode.B source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase14: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase14: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase14: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase14: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase14: cn.chenforcode.B source()>()");

        sinkMethod.add("<cn.chenforcode.SensetiveTestCase15: void sink(cn.chenforcode.C)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase15: void sink(cn.chenforcode.A)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase15: void sink(cn.chenforcode.B)>");
        sinkMethod.add("<cn.chenforcode.SensetiveTestCase15: void sink(int)>");
        sourceMethod.add("<cn.chenforcode.SensetiveTestCase15: cn.chenforcode.B source()>()");

        //其余sink和source
        sinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String)>");
        sinkMethod.add("<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        sinkMethod.add("<java.sql.PreparedStatement: boolean execute()>");
        sinkMethod.add("<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        sinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String)>");
        sinkMethod.add("<java.sql.Statement: int[] executeBatch()>");
        sinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String,int)>");
        sinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String,int[])>");
        sinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String,java.lang.String[])>");
        sinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String,int)>");
        sinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String,int[])>");
        sinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String,java.lang.String[])>");
        sinkMethod.add("<java.sql.Statement: long[] executeLargeBatch()>");
        sinkMethod.add("<java.sql.Statement: long executeLargeUpdate(java.lang.String,int)>");
        sinkMethod.add("<java.sql.Statement: long executeLargeUpdate(java.lang.String,int[])>");
        sinkMethod.add("<java.sql.Statement: long executeLargeUpdate(java.lang.String,java.lang.String[])>");


        sourceMethod.add("<java.util.Properties: java.lang.String getProperty(java.lang.String)>");
        sourceMethod.add("<cn.chenforcode.StaticRef: int source()>");
        sourceMethod.add("<java.lang.System: java.lang.String getProperty(java.lang.String)>");
        sourceMethod.add("<java.io.BufferedReader: java.lang.String readLine()>");
        sourceMethod.add("<java.lang.System: java.lang.String getenv(java.lang.String)>");
        //httpServletRequest
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getQueryString()>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String[] getParameterValues(java.lang.String)>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.util.Enumeration getParameterNames()>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.util.Map getParameterMap()>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.HttpSession getSession()>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getRequestedSessionId()>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.HttpSession getSession(boolean)>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.Cookie[] getCookies()>");
        sourceMethod.add("<java.sql.ResultSet: java.lang.String getString(int)>");//todo 对应的应该还有getInt等


//        下面是xss的source和sink
        sourceMethod.add("<java.io.BufferedReader: java.lang.String readLine()>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.Cookie[] getCookies()>");
        sourceMethod.add("<java.sql.ResultSet: java.lang.String getString(int)>");
        sourceMethod.add("<java.util.Properties: java.lang.String getProperty(java.lang.String)>");
        sourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getQueryString()>");

        sinkMethod.add("<java.io.PrintWriter: void println(java.lang.String)>");
        sinkMethod.add("<javax.servlet.http.HttpServletResponse: void sendError(int,java.lang.String)>");

    }

    public boolean isSink(String methodName) {
        for (String s : sinkMethod) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }


    public boolean isSource(String methodName) {
        for (String s : sourceMethod) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isInitMethod(String methodName) {
        for (String s : initMethod) {
            if (s.equals(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isArgToInvoke(String methodName) {
        for (String s : argToInvoke) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isToStringMethod(String methodName) {
        for (String s : toStringMethod) {
            if (s.equals(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isInvokeToLeft(String methodName) {
        for (String s : invokeToLeft) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isValueOfMethod(String methodName) {
        for (String s : valueOfMethod) {
            if (s.equals(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isArgToLeft(String methodName) {
        for (String s : argToLeft) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isInvokeArgToLeft(String methodName) {
        for (String s : invokeArgToLeft) {
            if (s.equals(methodName)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
        EndpointConstant endpointConstant = new EndpointConstant();
        System.out.println(endpointConstant.isSink("sink"));
        System.out.println(endpointConstant.isSource("source"));
        System.out.println(endpointConstant.isSink("abc"));
    }
}
