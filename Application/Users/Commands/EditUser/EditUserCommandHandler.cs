using AutoMapper;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core.Entities;

namespace Application.Users.Commands.EditUser
{
    public class EditUserCommandHandler : IRequestHandler<EditUserCommand, List<string>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<EditUserCommandHandler> _logger;

        public EditUserCommandHandler(UserManager<ApplicationUser> userManager, ILogger<EditUserCommandHandler> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<List<string>> Handle(EditUserCommand request, CancellationToken cancellationToken)
        {
            List<string> errors = new();
            ApplicationUser user = await _userManager.FindByIdAsync(request.Id);
            if (user == null)
            {
                errors.Add($"Unable to find user with id {request.Id}");
            }
            List<IdentityError> identityErrors = new();
            // change password if not null
            string newPassword = request.Password;
            if (!string.IsNullOrWhiteSpace(newPassword))
            {
                string passResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                IdentityResult passResetResult = await _userManager.ResetPasswordAsync(user, passResetToken, newPassword);
                if (passResetResult.Succeeded)
                {
                    _logger.LogInformation("User password changed");
                }
                else
                {
                    identityErrors.AddRange(passResetResult.Errors);
                }
            }

            // change username if changed
            if (user.UserName != request.Username)
            {
                IdentityResult usernameChangeResult = await _userManager.SetUserNameAsync(user, request.Username);
                if (usernameChangeResult.Succeeded)
                {
                    _logger.LogInformation("Username changed");

                }
                else
                {
                    identityErrors.AddRange(usernameChangeResult.Errors);
                }
            }

            // change email if changed
            if (user.Email != request.Email)
            {
                string emailResetToken = await _userManager.GenerateChangeEmailTokenAsync(user, request.Email);
                IdentityResult emailChangeResult = await _userManager.ChangeEmailAsync(user, request.Email, emailResetToken);
                if (emailChangeResult.Succeeded)
                {
                    _logger.LogInformation("email changed");
                }
                else
                {
                    identityErrors.AddRange(emailChangeResult.Errors);
                }
            }

            // change phone number if changed
            if (user.PhoneNumber != request.PhoneNumber)
            {
                string phoneChangeToken = await _userManager.GenerateChangePhoneNumberTokenAsync(user, request.PhoneNumber);
                IdentityResult phoneChangeResult = await _userManager.ChangePhoneNumberAsync(user, request.PhoneNumber, phoneChangeToken);
                if (phoneChangeResult.Succeeded)
                {
                    _logger.LogInformation($"phone number of user {user.UserName} with id {user.Id} changed to {request.PhoneNumber}");
                }
                else
                {
                    identityErrors.AddRange(phoneChangeResult.Errors);
                }
            }

            // change user role if not present in user
            bool isValidRole = SecurityConstants.GetRoles().Contains(request.UserRole);
            List<string> existingUserRoles = (await _userManager.GetRolesAsync(user)).ToList();
            bool isRoleChanged = !existingUserRoles.Any(r => r == request.UserRole);
            if (isValidRole)
            {
                if (isRoleChanged)
                {
                    // remove existing user roles if any
                    await _userManager.RemoveFromRolesAsync(user, existingUserRoles);
                    // add new Role to user from VM
                    await _userManager.AddToRoleAsync(user, request.UserRole);
                }
            }

            // update DisplayName
            if (user.DisplayName != request.DisplayName)
            {
                user.DisplayName = request.DisplayName;
                await _userManager.UpdateAsync(user);
            }

            // update IsActive
            if (user.IsActive != request.IsActive)
            {
                user.IsActive = request.IsActive;
                await _userManager.UpdateAsync(user);
            }

            foreach (IdentityError iError in identityErrors)
            {
                errors.Add(iError.Description);
            }
            return errors;
        }
    }
}
