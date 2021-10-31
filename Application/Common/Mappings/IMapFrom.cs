using AutoMapper;

namespace Application.Common.Mappings
{
    public partial class MappingProfile
    {
        public interface IMapFrom<T>
        {
            void Mapping(Profile profile) => profile.CreateMap(typeof(T), GetType());
        }
    }
}
