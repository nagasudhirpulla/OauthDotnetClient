using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentValidation.AspNetCore;
using FluentValidation.Results;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Application.Users;
using Application.Users.Commands.CreateUser;
using WebApp.Extensions;

namespace WebApp.Pages.Users
{
    [Authorize(Roles = SecurityConstants.AdminRoleString)]
    public class CreateModel : PageModel
    {
        private readonly ILogger _logger;
        private readonly IMediator _mediator;

        public CreateModel(ILogger<IndexModel> logger, IMediator mediator)
        {
            _logger = logger;
            _mediator = mediator;
        }

        //https://www.learnrazorpages.com/razor-pages/forms/select-lists
        public SelectList URoles { get; set; }

        [BindProperty]
        public CreateUserCommand NewUser { get; set; }

        public void OnGet()
        {
            InitSelectListItems();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            InitSelectListItems();

            ValidationResult validationCheck = new CreateUserCommandValidator().Validate(NewUser);
            validationCheck.AddToModelState(ModelState, nameof(NewUser));

            if (!ModelState.IsValid)
            {
                return Page();
            }

            IdentityResult result = await _mediator.Send(NewUser);
            if (result.Succeeded)
            {
                _logger.LogInformation($"Created new account for {NewUser.Username}");
                return RedirectToPage($"./{nameof(Index)}").WithSuccess($"Created new user {NewUser.Username}");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();

        }

        public void InitSelectListItems()
        {
            URoles = new SelectList(SecurityConstants.GetRoles());
        }
    }
}
