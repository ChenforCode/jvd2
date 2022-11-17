package pku.jvd.analysis.taint.abstraction;

import java.util.ArrayList;
import java.util.List;

public class XSSEndpointConstant extends EndpointConstant {
    private List<String> xssSinkMethod = new ArrayList<>();
    private List<String> xssSourceMethod = new ArrayList<>();

    public XSSEndpointConstant() {
        xssSourceMethod.add("<java.io.BufferedReader: java.lang.String readLine()>");
        xssSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)>");
        xssSourceMethod.add("<javax.servlet.http.HttpServletRequest: javax.servlet.http.Cookie[] getCookies()>");
        xssSourceMethod.add("<java.sql.ResultSet: java.lang.String getString(int)>");
        xssSourceMethod.add("<java.util.Properties: java.lang.String getProperty(java.lang.String)>");
        xssSourceMethod.add("<javax.servlet.http.HttpServletRequest: java.lang.String getQueryString()>");

        xssSinkMethod.add("<java.io.PrintWriter: void println(java.lang.String)>");
        xssSinkMethod.add("<javax.servlet.http.HttpServletResponse: void sendError(int,java.lang.String)>");
    }

    @Override
    public boolean isSink(String methodName) {
        for (String s : xssSinkMethod) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isSource(String methodName) {
        for (String s : xssSourceMethod) {
            if (s.contains(methodName)) {
                return true;
            }
        }
        return false;
    }
}
