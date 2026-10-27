import java.sql.*;
import java.util.Set;
import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {
    private static final Set<String> COLUMNS = Set.of("created", "total", "status");
    private Connection conn;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String sort = req.getParameter("sort");
        if (!COLUMNS.contains(sort)) {
            resp.sendError(400);
            return;
        }
        Statement st = conn.createStatement();
        resp.getWriter().print(st.executeQuery("SELECT * FROM reports ORDER BY " + sort));  // AI:safe
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String sort = req.getParameter("sort");
        Statement st = conn.createStatement();
        resp.getWriter().print(st.executeQuery("SELECT * FROM reports ORDER BY " + sort));  // AI:real
    }
}
