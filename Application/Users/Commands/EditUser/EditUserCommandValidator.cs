using FluentValidation;
using System;

namespace Application.Users.Commands.EditUser
{
    public class EditUserCommandValidator : AbstractValidator<EditUserCommand>
    {
        public EditUserCommandValidator()
        {
            RuleFor(x => x.Id).NotEmpty();
            RuleFor(x => x.Username).NotEmpty();
            RuleFor(x => x.DisplayName).NotEmpty();
            RuleFor(x => x.Email).EmailAddress().NotEmpty();
            RuleFor(x => x.UserRole).NotEmpty();
            RuleFor(x => x.Password)
                .Equal(x => x.ConfirmPassword).WithMessage("Password and confirmation password do not match.");
        }
    }
}
