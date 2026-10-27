import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

// Servlet where user input travels through helper methods, plus look-alike safe code.
public class OrderServlet extends HttpServlet {
    private static final String ORDERS = "orders";
    private static final String EXPORT_DIR = "/srv/exports";
    private Connection conn;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String status = req.getParameter("status");
        resp.getWriter().println(lookup(status));
        String fileName = req.getParameter("file");
        File export = new File(EXPORT_DIR, fileName);
        int page = Integer.parseInt(req.getParameter("page"));
        resp.getWriter().println(pageOf(page));
        String note = req.getParameter("note");
        resp.getWriter().println("<p>" + note + "</p>");
    }

    private String lookup(String orderStatus) throws SQLException {
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM " + ORDERS + " WHERE status = '" + orderStatus + "'");
        return rs.toString();
    }

    public int total() throws SQLException {
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM " + ORDERS);
        return rs.getInt(1);
    }

    private String pageOf(int page) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM orders LIMIT 20 OFFSET " + (page * 20)).toString();
    }
}
