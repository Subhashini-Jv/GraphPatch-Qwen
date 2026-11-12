package demo;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

/** Deliberately vulnerable demo (OS command injection, CWE-78). */
public class Ping {
    public Process ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
