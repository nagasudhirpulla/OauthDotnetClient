using AutoMapper;
using MediatR;
using System.Collections.Generic;
using System.Text;
using Application.Users.Queries.GetAppUsers;
using Core.Entities;
using static Application.Common.Mappings.MappingProfile;

namespace Application.Users.Commands.EditUser
{
    public class EditUserCommand : IRequest<List<string>>, IMapFrom<UserDTO>
    {
        public string Id { get; set; }
        public string Username { get; set; }
        public string DisplayName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
        public string UserRole { get; set; }
        public bool IsActive { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<ApplicationUser, EditUserCommand>()
                .ForMember(d => d.Username, opt => opt.MapFrom(s => s.UserName));
        }
    }
}
