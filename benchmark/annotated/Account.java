import java.io.*;
import java.security.MessageDigest;
import java.sql.*;

// Deliberately vulnerable Java class (benchmark fixture).
public class Account {
    private static final String DB_PASS = "J4vaS3cret!x";  // VULN:hardcoded_secret

    public ResultSet find(Connection conn, String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM accounts WHERE name = '" + name + "'");  // VULN:sqli
    }

    public ResultSet findSafe(Connection conn, String name) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }

    public void archive(String dir) throws IOException {
        Runtime.getRuntime().exec("tar czf backup.tgz " + dir);  // VULN:cmdi
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);  // VULN:weak_crypto
    }

    public Object restore(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);  // VULN:deserialization
        return ois.readObject();
    }
}
