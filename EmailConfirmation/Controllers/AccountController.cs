using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<html>");

            return builder.ToString();
        }

        private async Task<IdentityUser?> GetUser(string email) => await userManager.FindByEmailAsync(email);
    }
}
