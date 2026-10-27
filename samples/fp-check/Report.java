import java.sql.*;

public class Report {
    private static final String TABLE_NAME = "monthly_sales";

    public ResultSet totals(Connection conn) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT region, SUM(amount) FROM " + TABLE_NAME + " GROUP BY region");
    }
}
