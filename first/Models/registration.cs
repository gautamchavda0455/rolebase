using System.ComponentModel.DataAnnotations;

namespace first.Models
{
    public class registration
    {
        [Required]
        public string Name { get; set; }

        [Required]
        [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
         ErrorMessage = "Enter a valid email address (e.g., user@example.com).")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long.")]
        public string Password { get; set; }

        public string Userrole { get; set; } = "User";
        public byte freez { get; set; } = 0;
    }


}
