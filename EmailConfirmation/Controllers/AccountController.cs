using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace EmailConfirmation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {
        [HttpPost]
        [Route("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            var user = await GetUser(email);
            if (user != null)
            {
                return BadRequest();
            }
            var result = await userManager.CreateAsync(new IdentityUser
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            }, password);
            if(!result.Succeeded)
            {
                return BadRequest();
            }

            var _user = await GetUser(email);
            var emailCode = await userManager.GenerateEmailConfirmationTokenAsync(_user!);
            string sendEmail = SendEmail(_user!.Email!, emailCode);
            return Ok();
        }

        private string SendEmail(string email, string emailCode)
        {
            var builder = new StringBuilder();
            builder.AppendLine("<html>");
            builder.AppendLine("<body>");
            builder.AppendLine($"<p>Dear {email},</p>");
            builder.AppendLine("<p>Thank you for registering with us. To verify your email address, please use the following verification code:</p>");
            builder.AppendLine($"<h2>Verification Code: {emailCode}</h2>");
            builder.AppendLine("<p>Please enter this code on our website to complete the registration.</p>");
            builder.AppendLine("<p>If you did not request this, please ignore this email.</p>");
            builder.AppendLine("<br>");
            builder.AppendLine("<p>Best regard,</p>");
            builder.AppendLine("<p><strong>Phantom</strong></p>");
            builder.AppendLine("</body>");
            builder.AppendLine("</html>");

            var message = builder.ToString();
            var _email = new MimeMessage();
            _email.To.Add(MailboxAddress.Parse(""));
            _email.From.Add(MailboxAddress.Parse(""));
            _email.Subject = "Email Confirmation";
            _email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message };
            using var smtp = new SmtpClient();
            smtp.Connect("", , MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("", "");
            smtp.Send(_email);
            smtp.Disconnect(true);
            return "Thank you for your registration, kindly check your email for confirmation code";
        }

        [HttpPost]
        [Route("confirmation/{email}/{code:int}")]
        public async Task<IActionResult> Confirmation(string email, int code)
        {
            if (string.IsNullOrEmpty(email) || code <= 0)
                return BadRequest("Invalid code provider");
            var user =await GetUser(email);
            if (user == null) return BadRequest("Invalid identity provider");

            var result = await userManager.ConfirmEmailAsync(user, code.ToString());
            return !result.Succeeded ? BadRequest("Invalid code provider")
                : Ok("Email confirmed successfully, you can proceed to login");

        }

        [HttpPost]
        [Route("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                return BadRequest();
            }
            var user = await GetUser(email);
            bool isEmailConfirmed = await userManager.IsEmailConfirmedAsync(user!);
            if (!isEmailConfirmed)
            {
                return BadRequest("You need to confirm email before logginning in");
            }
            return Ok(new[] { "Login Successfully", GenerateToken(user) });
        }

        private string GenerateToken(IdentityUser? user)
        {
            byte[] key = Encoding.ASCII.GetBytes("VtzRpiXT4kU95jvHYrW8v06n2839myaP");
            var securityKey = new SymmetricSecurityKey(key);
            var credential = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user!.Id),
                new Claim(JwtRegisteredClaimNames.Email, user!.Email!),
            };

            var token = new JwtSecurityToken
                (issuer: null, audience: null, claims: claims, expires: null, signingCredentials: credential);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private async Task<IdentityUser?> GetUser(string email) => await userManager.FindByEmailAsync(email);

        [HttpGet("protected")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public string GetMessage() => "This message is coming from protected endpoint";
    }
}
