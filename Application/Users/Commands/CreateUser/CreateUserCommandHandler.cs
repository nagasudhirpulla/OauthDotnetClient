using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;
using Core.Entities;

namespace Application.Users.Commands.CreateUser
{
    public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, IdentityResult>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<CreateUserCommandHandler> _logger;

        public CreateUserCommandHandler(UserManager<ApplicationUser> userManager, IEmailSender emailSender, ILogger<CreateUserCommandHandler> logger)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        public async Task<IdentityResult> Handle(CreateUserCommand request, CancellationToken cancellationToken)
        {
            ApplicationUser user = new()
            {
                UserName = request.Username,
                DisplayName = request.DisplayName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                IsActive = request.IsActive
            };
            IdentityResult result;
            if (request.Password == null)
            {
                // password was not passed, hence creating user without a password
                result = await _userManager.CreateAsync(user);
            }
            else
            {
                result = await _userManager.CreateAsync(user, request.Password);
            }
            if (result.Succeeded)
            {
                _logger.LogInformation($"Created new account for {user.UserName} with id {user.Id}");
                // check if role string is valid
                bool isValidRole = SecurityConstants.GetRoles().Contains(request.UserRole);
                if (isValidRole)
                {
                    await _userManager.AddToRoleAsync(user, request.UserRole);
                    _logger.LogInformation($"{request.UserRole} role assigned to new user {user.UserName} with id {user.Id}");
                }
                // verify user email
                string emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                IdentityResult emaiVerifiedResult = await _userManager.ConfirmEmailAsync(user, emailToken);
                if (emaiVerifiedResult.Succeeded)
                {
                    _logger.LogInformation($"Email verified for new user {user.UserName} with id {user.Id} and email {user.Email}");
                }
                else
                {
                    _logger.LogInformation($"Email verify failed for {user.UserName} with id {user.Id} and email {user.Email} due to errors {emaiVerifiedResult.Errors}");
                }

                if (!string.IsNullOrWhiteSpace(user.PhoneNumber))
                {
                    // verify phone number
                    string phoneVerifyToken = await _userManager.GenerateChangePhoneNumberTokenAsync(user, user.PhoneNumber);
                    IdentityResult phoneVeifyResult = await _userManager.ChangePhoneNumberAsync(user, user.PhoneNumber, phoneVerifyToken);
                    _logger.LogInformation($"Phone verified new user {user.UserName} with id {user.Id} and phone {user.PhoneNumber} = {phoneVeifyResult.Succeeded}");
                }
                /**
                // send confirmation email to user
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callbackUrl = QueryHelpers.AddQueryString(request.BaseUrl, new Dictionary<string, string>() { { "code", code }, { "userId", user.Id } });
                try
                {
                    await _emailSender.SendEmailAsync(
                    user.Email,
                    "Please confirm your email for WRLDC Shift Roster web app",
                    $"Please confirm your account of WRLDC Shift Roster web app by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>");
                    Console.WriteLine($"Email address Confirmation mail sent to ${user.UserName}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                **/
            }
            return result;
        }
    }
}
