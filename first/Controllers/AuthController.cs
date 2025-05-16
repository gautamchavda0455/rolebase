using System.Data.Common;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using first.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace first.Controllers
{
    public class AuthController : Controller
    {

      
            private readonly ILogger<AuthController> _logger;
            private readonly string _connectionString;

            public AuthController(IConfiguration configuration)
            {
                _connectionString = configuration.GetConnectionString("PostgresConnection");
            }
           
            public IActionResult register()
            {
                return View("~/Views/NewFolder/register.cshtml");
            }

            public IActionResult Login()
            {
                return View("~/Views/NewFolder/login.cshtml");
            }
            public IActionResult Homepage()
            {
                return View("~/Views/NewFolder/Homepage.cshtml");
            }
            public IActionResult AdminDashboardView()
            {
                AdminDashboard();
                return View("~/Views/NewFolder/AdminDashboard.cshtml");
            }

            public IActionResult ListUsers()
            {
                AdminDashboard();
                return View("~/Views/NewFolder/ListUsers.cshtml");
            }
            [HttpPost]
            public IActionResult Register1(registration model)
            {
                if (!ModelState.IsValid)
                {
                    return View("Register", model);
                }
                try
                {
                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    //DropUsersTableIfExists(conn);
                    if (!TableExists(conn, "users"))
                    {
                        CreateUsersTable(conn);
                    }

                    var checkCommand = new NpgsqlCommand("SELECT COUNT(*) FROM users WHERE email = @Email", conn);
                    checkCommand.Parameters.AddWithValue("@Email", model.Email);
                    var exists = (long)checkCommand.ExecuteScalar();

                    if (exists > 0)
                    {
                        return Content("<script>alert('A user with this email already exists.'); window.history.back();</script>", "text/html");
                    }



                    var insertCommand = new NpgsqlCommand(
                                    @"INSERT INTO users (name, email, password, userrole,freez)
                                  VALUES (@Name, @Email, @Password, @UserRole,@freez)", conn);

                    insertCommand.Parameters.AddWithValue("@Name", model.Name);
                    insertCommand.Parameters.AddWithValue("@Email", model.Email);
                    insertCommand.Parameters.AddWithValue("@Password", model.Password);
                    insertCommand.Parameters.AddWithValue("@UserRole", model.Userrole ?? "User");
                    insertCommand.Parameters.AddWithValue("@freez", model.freez);

                    insertCommand.ExecuteNonQuery();


                    TempData["Success"] = "User registered successfully!";
                    return RedirectToAction("Login");
                    // return Content("User registered successfully");

                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Database error: {ex.Message}");
                    return View("Register", model);
                }
            }
            private void DropUsersTableIfExists(NpgsqlConnection conn)
            {
                var dropCommand = new NpgsqlCommand("DROP TABLE IF EXISTS users", conn);
                dropCommand.ExecuteNonQuery();
            }
            public IActionResult authlogin(login model)
            {
                if (!ModelState.IsValid)
                {
                    return View("Login", model);
                }

                try
                {

                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    // Check user with role and freez status
                    var checkCommand = new NpgsqlCommand(
                        @"SELECT userrole, freez FROM users 
                 WHERE email = @Email AND password = @Password", conn);
                    checkCommand.Parameters.AddWithValue("@Email", model.Email);
                    checkCommand.Parameters.AddWithValue("@Password", model.Password);

                    using var reader = checkCommand.ExecuteReader();

                    if (!reader.Read())
                    {
                        ModelState.AddModelError("", "Invalid email or password.");
                        return View("Login", model);
                    }

                    var role = reader["userrole"]?.ToString()?.ToLower();
                    var freez = Convert.ToInt32(reader["freez"]);

                    if (freez != 0)
                    {
                        ModelState.AddModelError("", "Your account is frozen. Please contact admin.");
                        return View("Login", model);
                    }

                    // Generate JWT token
                    var token = GenerateJwtToken(model.Email);
                    if (string.IsNullOrEmpty(token))
                    {
                        ModelState.AddModelError("", "Token generation failed. Cannot log in.");
                        return View("Login", model);
                    }

                    HttpContext.Response.Cookies.Append("JWTToken", token, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict,
                        Expires = DateTimeOffset.UtcNow.AddDays(1)
                    });

                    TempData["Success"] = "Login successful!";

                    // Redirect based on role
                    if (role == "admin")
                    {
                        return RedirectToAction("AdminDashboardView");
                    }
                    else
                    {
                        return RedirectToAction("Homepage");
                    }
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Database error: {ex.Message}");
                    return View("Login", model);
                }
            }
            public IActionResult AdminDashboard()
            {
                try
                {
                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    var totalUsersCmd = new NpgsqlCommand("SELECT COUNT(*) FROM users", conn);
                    var adminCountCmd = new NpgsqlCommand("SELECT COUNT(*) FROM users WHERE userrole = 'admin'", conn);
                    var userCountCmd = new NpgsqlCommand("SELECT COUNT(*) FROM users WHERE userrole = 'User'", conn);

                    ViewBag.TotalUsers = (long)totalUsersCmd.ExecuteScalar();
                    ViewBag.AdminCount = (long)adminCountCmd.ExecuteScalar();
                    ViewBag.UserCount = (long)userCountCmd.ExecuteScalar();

                    return View("admindashboard");
                }
                catch (Exception ex)
                {
                    TempData["Error"] = "Failed to load dashboard: " + ex.Message;
                    return RedirectToAction("Login");
                }
            }
            public IActionResult ViewAdmin()
            {
                var users = new List<registration>();

                try
                {

                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    var cmd = new NpgsqlCommand("SELECT name, email, userrole FROM users where userrole = 'admin' ", conn);
                    var reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        users.Add(new registration
                        {
                            Name = reader.GetString(0),
                            Email = reader.GetString(1),
                            Userrole = reader.GetString(2)
                        });
                    }
                }
                catch (Exception ex)
                {
                    ViewBag.Error = $"Failed to load users: {ex.Message}";
                }

                // FIX: Directly return the view and pass the model
                return View("~/Views/NewFolder/ListAdmin.cshtml", users);
            }
            public IActionResult ViewUsers()
            {
                var users = new List<registration>();

                try
                {
                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    var cmd = new NpgsqlCommand("SELECT name, email, userrole ,freez FROM users where userrole = 'User' ", conn);
                    var reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        users.Add(new registration
                        {
                            Name = reader.GetString(0),
                            Email = reader.GetString(1),
                            Userrole = reader.GetString(2),
                            freez = reader.GetByte(3)
                        });
                    }
                }
                catch (Exception ex)
                {
                    ViewBag.Error = $"Failed to load users: {ex.Message}";
                }

                // FIX: Directly return the view and pass the model
                return View("~/Views/NewFolder/ListUsers.cshtml", users);
            }
            public IActionResult ToggleFreez(string email)
            {
                try
                {

                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    // Get current value
                    var getCmd = new NpgsqlCommand("SELECT freez FROM users WHERE email = @Email", conn);
                    getCmd.Parameters.AddWithValue("@Email", email);
                    var currentFreez = Convert.ToInt32(getCmd.ExecuteScalar());

                    // Toggle value: 0 -> 1, 1 -> 0
                    var newFreez = currentFreez == 0 ? 1 : 0;

                    var updateCmd = new NpgsqlCommand("UPDATE users SET freez = @Freez WHERE email = @Email", conn);
                    updateCmd.Parameters.AddWithValue("@Freez", newFreez);
                    updateCmd.Parameters.AddWithValue("@Email", email);
                    updateCmd.ExecuteNonQuery();

                    ViewBag.Message = "User freeze status updated.";
                }
                catch (Exception ex)
                {
                    ViewBag.Error = $"Error: {ex.Message}";
                }

                // Retrieve the updated list of users
                var users = new List<registration>();
                try
                {
                    using var conn = new NpgsqlConnection(_connectionString);
                    conn.Open();

                    var cmd = new NpgsqlCommand("SELECT name, email, userrole, freez FROM users where userrole = 'User'", conn);
                    using var reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        users.Add(new registration
                        {
                            Name = reader.GetString(0),
                            Email = reader.GetString(1),
                            Userrole = reader.GetString(2),
                            freez = reader.GetByte(3)
                        });
                    }
                }
                catch (Exception ex)
                {
                    ViewBag.Error = $"Error retrieving users: {ex.Message}";
                }

                return View("~/Views/NewFolder/ListUsers.cshtml", users);
            }
            private string GenerateJwtToken(string email)
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("this-is-a-very-strong-secret-key!123"));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new[]
                {
            new Claim(JwtRegisteredClaimNames.Sub, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

                var token = new JwtSecurityToken(
                    issuer: "your-app",
                    audience: "your-app",
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: credentials
                );

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            private bool TableExists(NpgsqlConnection connection, string tableName)
            {
                var checkTableCommand = new NpgsqlCommand(
                    @"SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = @tableName
        )", connection);

                checkTableCommand.Parameters.AddWithValue("@tableName", tableName);
                return (bool)checkTableCommand.ExecuteScalar();
            }
            private void CreateUsersTable(NpgsqlConnection connection)
            {
                var createTableCommand = new NpgsqlCommand(
                     @"CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    userrole VARCHAR(50) DEFAULT 'User',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    freez SMALLINT DEFAULT 0
                );", connection);


                createTableCommand.ExecuteNonQuery();
            }

            [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
            public IActionResult Error()
            {
                return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
            }
        }

}
