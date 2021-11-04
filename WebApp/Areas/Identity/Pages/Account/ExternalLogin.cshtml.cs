using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Core.Entities;
using Application.Users.Commands.CreateUser;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using MediatR;
using WebApp.Extensions;

namespace WebApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ExternalLoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<ExternalLoginModel> _logger;
        private readonly IMediator _mediator;

        public ExternalLoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<ExternalLoginModel> logger,
            IEmailSender emailSender,
            IMediator mediator)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
            _emailSender = emailSender;
            _mediator = mediator;
        }

        [TempData]
        public string ErrorMessage { get; set; }

        public string ProviderDisplayName { get; set; }

        public IActionResult OnGetAsync()
        {
            return RedirectToPage("./Login");
        }

        public IActionResult OnPost(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        public async Task<IActionResult> OnGetCallbackAsync(string returnUrl = null, string remoteError = null)
        {
            returnUrl ??= Url.Content("~/");
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ErrorMessage = "Error loading external login information.";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }


            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl });
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
            }
            else
            {
                // TODO check this
                bool isEmailPresent = info.Principal.HasClaim(c => c.Type == ClaimTypes.Email);
                if (isEmailPresent)
                {
                    string usrEmail = info.Principal.FindFirstValue(ClaimTypes.Email);
                    //check if user already exists with this email
                    var usr = await _userManager.FindByEmailAsync(usrEmail);
                    if (usr == null)
                    {
                        string oAuthUname = info.Principal.Identity.Name;
                        string newUname = oAuthUname;
                        if ((await _userManager.FindByNameAsync(oAuthUname)) != null)
                        {
                            // create a unique username if already exists
                            newUname = Guid.NewGuid().ToString();
                        }
                        // create user if not present

                        IdentityResult createUsrResult = await _mediator.Send(new CreateUserCommand()
                        {
                            Username = oAuthUname,
                            Email = usrEmail
                        });

                        if (createUsrResult.Succeeded)
                        {
                            _logger.LogInformation($"Created new account for {usrEmail} with {oAuthUname} as username");
                        }

                    }
                    // Add a login (i.e insert a row for the user in AspNetUserLogins table)
                    _ = await _userManager.AddLoginAsync(usr, info);
                    // sign in the user again
                    result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
                    if (result.Succeeded)
                    {
                        _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity.Name, info.LoginProvider);
                        return LocalRedirect(returnUrl);
                    }
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl });
                    }
                    if (result.IsLockedOut)
                    {
                        return RedirectToPage("./Lockout");
                    }
                }
            }
            // Some issue occured
            ProviderDisplayName = info.ProviderDisplayName;
            return Page();
        }
    }
}
