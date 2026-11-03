import java.sql.*;
import javax.servlet.http.*;
public class Vuln extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String user = req.getParameter("user");
    Statement st = DriverManager.getConnection("jdbc:sqlite:app.db").createStatement();
    ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    Runtime.getRuntime().exec("ping " + req.getParameter("host"));
    res.getWriter().println(rs.getString(1));
  }
}
