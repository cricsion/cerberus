using System.Data.SqlClient;
using System.Diagnostics;
public class Program {
  public static void Main(string[] args) {
    var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + args[0] + "'");
    Process.Start("ping", args[1]);
  }
}
