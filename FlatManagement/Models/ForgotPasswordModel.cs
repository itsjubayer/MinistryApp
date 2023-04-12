using System.ComponentModel.DataAnnotations;

namespace FlatManagement.Models
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
