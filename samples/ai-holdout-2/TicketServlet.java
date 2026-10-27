import java.sql.*;
import javax.servlet.http.*;

public class TicketServlet extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        if (id == null || id.length() > 20) {
            resp.sendError(400);
            return;
        }
        Statement st = conn.createStatement();
        resp.getWriter().print(st.executeQuery("SELECT * FROM tickets WHERE ref = '" + id + "'"));
    }
}
