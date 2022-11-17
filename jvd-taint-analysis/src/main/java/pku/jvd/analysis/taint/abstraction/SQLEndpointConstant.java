package pku.jvd.analysis.taint.abstraction;

import java.util.ArrayList;
import java.util.List;

public class SQLEndpointConstant extends EndpointConstant {
    private List<String> sqlSinkMethod = new ArrayList<>();
    private List<String> sqlSourceMethod = new ArrayList<>();

    public SQLEndpointConstant() {
        sqlSinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String)>");
        sqlSinkMethod.add("<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
//        sqlSinkMethod.add("<java.sql.PreparedStatement: boolean execute()>");
        sqlSinkMethod.add("<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        sqlSinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String)>");
        sqlSinkMethod.add("<java.sql.Statement: int[] executeBatch()>");
        sqlSinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String,int)>");
        sqlSinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String,int[])>");
        sqlSinkMethod.add("<java.sql.Statement: boolean execute(java.lang.String,java.lang.String[])>");
        sqlSinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String,int)>");
        sqlSinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String,int[])>");
        sqlSinkMethod.add("<java.sql.Statement: int executeUpdate(java.lang.String,java.lang.String[])>");
        sqlSinkMethod.add("<java.sql.Statement: long[] executeLargeBatch()>");
        sqlSinkMethod.add("<java.sql.Statement: long executeLargeUpdate(java.lang.String,int)>");
        sqlSinkMethod.add("<java.sql.Statement: long executeLargeUpdate(java.lang.String,int[])>");
        sqlSinkMethod.add("<java.sql.Statement: long executeLargeUpdate(java.lang.String,java.lang.String[])>");
        sqlSinkMethod.add("<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String)>");


        sqlSourceMethod.add("<java.util.Properties: java.lang.String getProperty(java.lang.String)>");
        sqlSourceMethod.add("<cn.chenforcode.StaticRef: int source()>");
        sqlSourceMethod.add("<java.lang.System: java.lang.String getProperty(java.lang.String)>");
        sqlSourceMethod.add("<java.io.BufferedReader: java.lang.String readLine()>");
        sqlSourceMethod.add("<java.lang.System: java.lang.String getenv(java.lang.String)>");
        //httpServletRequest
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getQueryString()>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String[] getParameterValues(java.lang.String)>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.util.Enumeration getParameterNames()>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.util.Map getParameterMap()>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.HttpSession getSession()>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getRequestedSessionId()>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.HttpSession getSession(boolean)>");
        sqlSourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.Cookie[] getCookies()>");
        sqlSourceMethod.add("<java.sql.ResultSet: java.lang.String getString(int)>");//todo 对应的应该还有getInt等
    }

    @Override
    public boolean isSink(String methodName) {
        for (String s : sqlSinkMethod) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isSource(String methodName) {
        for (String s : sqlSourceMethod) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }
}
