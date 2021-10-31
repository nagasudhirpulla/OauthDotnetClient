using System;

namespace Core.Common
{
    public class AuditableEntity: BaseEntity
    {
        public string CreatedBy { get; set; }

        public DateTime Created { get; set; } = DateTime.Now;

        public string LastModifiedBy { get; set; }

        public DateTime? LastModified { get; set; }
    }
}
