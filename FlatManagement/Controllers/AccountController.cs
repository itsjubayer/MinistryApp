using FlatManagement.Models;
using FlatManagement.Utility;
using FlatManagement.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FlatManagement.Controllers
{
    //[Authorize]
    public class AccountController : Controller
    {
        private readonly MinistryDBContext _context;
        private readonly IWebHostEnvironment _hostingEnvironment;


        const string APARTCODEVAR = "_ApartCodeSession";
        const string APARTCOMPANYNAME = "_ApartCompanyName";
        const string APARTCOMPANYLOGO = "_ApartCompanyLogo";

        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        public AccountController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
                                SignInManager<ApplicationUser> signInManager, MinistryDBContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostingEnvironment = hostingEnvironment;
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.signInManager = signInManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(
                    model.Email, model.Password, model.RememberMe, false);
                
                if (result.Succeeded)
                {

                   var getValidUser = (from u in _context.Users
                                    where u.IsActive == true && u.Email== model.Email
                                       select u.UserName).FirstOrDefault();
                    if (getValidUser != null)
                    {
                        try
                        {
                            string userName = getValidUser;
                            

                            

                               
                            ViewBag.CodeName = HttpContext.Session.GetString(APARTCODEVAR);
                            ViewBag.CompanyName = HttpContext.Session.GetString(APARTCOMPANYNAME);
                            ViewBag.CompanyLogo = HttpContext.Session.GetString(APARTCOMPANYLOGO);

                        }
                        catch
                        {
                            ViewBag.CodeName = "";
                            ViewBag.CompanyName = "";
                            ViewBag.CompanyLogo = "";
                        }

                        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                        {
                            return Redirect(returnUrl);
                        }
                        else
                        {
                            return RedirectToAction("index", "home");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
                    }
                }

                ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
            }
            return View(model);
        }






        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {

            if (!ModelState.IsValid)
                return View(forgotPasswordModel);
            var user = await userManager.FindByEmailAsync(forgotPasswordModel.Email);
            if (user == null)
            {
                ViewBag.Message = "User not found!!";
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }
               
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var callback = Url.Action(nameof(ResetPassword), "Account", new { token, email = user.Email }, Request.Scheme);
            BroadCast bc = new BroadCast();
            bc.sendBroadCastMail("EMAIL", user.Email, "Reset password token "+ callback,"Password Reset -NIBASH CORE", "");

            // var message = new Message(new string[] { user.Email }, "Reset password token", callback, null);
            // await _emailSender.SendEmailAsync(message);
            ViewBag.Message = "Successful!!";
            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordModel { Token = token, Email = email };
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            if (!ModelState.IsValid)
                return View(resetPasswordModel);
            var user = await userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user == null)
                RedirectToAction(nameof(ResetPasswordConfirmationFailed));
            var resetPassResult = await userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.Password);
            if (!resetPassResult.Succeeded)
            {
                foreach (var error in resetPassResult.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return View();
            }
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmationFailed()
        {
            return View();
        }
        







        [AcceptVerbs("Get", "Post")]//[HttpGet][HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> IsEmailInUse(string email)
        {
            var user = await userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return Json(true);
            }
            else
            {
                return Json($"Email {email} is already in use.");
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            Remove("COMCODE");
            Remove("COMNAME");
            Remove("COMLOGO");

            Remove("BILLMENU");
            Remove("HOUSERENTMENU");
            Remove("FUNDMANAGEMENTMENU");
            Remove("MEETINGMANAGEMENTMENU");
            Remove("MAINTENANCEMENU");
            Remove("MESSAGEMENU");
            Remove("SETTINGSMENU");


            return RedirectToAction("index", "home");
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> SignOff()
        {
            await signInManager.SignOutAsync();
            //Remove("COMCODE");
            //Remove("COMNAME");
            //Remove("COMLOGO");
            return RedirectToAction("index", "home");
        }

        /// <summary>  
        /// Delete the key  
        /// </summary>  
        /// <param name="key">Key</param>  
        public void Remove(string key)
        {
            Response.Cookies.Delete(key);
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            var APART_CODE_LOCAL_VAR = HttpContext.Request.Cookies["COMCODE"];
            
    
            
         return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model, IFormFile uploadFile)
        {
            var APART_CODE_LOCAL_VAR = HttpContext.Request.Cookies["COMCODE"];
            var APART_APART_LOCAL_VAR = HttpContext.Request.Cookies["COMNAME"];
            ModelState.Clear();
            int validData = 0;

            var flat_no_var = model.Flat_No;
            if (ModelState.IsValid)
            {

                string uniqueFileName = null;
                if (uploadFile != null && uploadFile.Length > 0)
                {
                    string uploadsFolder = Path.Combine(_hostingEnvironment.WebRootPath, "ProfilePicture");
                    uniqueFileName = DateTime.Now.ToString("yymmssfff") + "_" + Path.GetFileName(uploadFile.FileName);
                    // uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(uploadFile.FileName);
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await uploadFile.CopyToAsync(fileStream);
                    }
                    model.ProfilePicture = uniqueFileName;
                    validData = 1;
                }
                else
                {
                    model.ProfilePicture = "no_picture.png";
                }

                if(model.TenantValue == "Tenant")
                {
                    model.Tenant = true;
                    model.IsLiving = true;

                }
                else  /////if (model.TenantValue=User) or model.TenantValue= ""////
                {
                        validData = 1; 
                        model.Tenant = false;
                        if (model.RealFlatOwner != null)
                        {
                            model.FlatOwner = model.RealFlatOwner;
                            model.RealFlatOwner = "";

                        }
                        else
                        {
                            model.FlatOwner = model.Email;
                            model.IsRealFlatOwner = true;
                        }

                        model.IsLiving = true;
                }

                if (validData == 1)
                {
                    var user = new ApplicationUser
                    {
                        UserName = model.Email,
                        Email = model.Email,
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Mobile = model.Mobile,
                        NID = model.NID,
                        ETIN = model.ETIN,
                        PassportNo = model.PassportNo,
                        Per_Address = model.Per_Address,
                        pre_Address = model.pre_Address,
                        UserRole = model.UserRole,
                        ProfilePicture = model.ProfilePicture,
                        IsActive = true
                    };

                    var result = await userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        var RoleFlatOwner = roleManager.FindByNameAsync(EnumRoleLists.Chamber.ToString()).Result;
                        if (RoleFlatOwner != null)
                        {
                            var roleresult = await userManager.AddToRoleAsync(user, EnumRoleLists.Chamber.ToString());
                        }

                        string smsBody = "Welcome to " + APART_APART_LOCAL_VAR + ". Thank you for using NIBASH(Flat Management System).";
                        BroadCast nB = new BroadCast();
                        nB.sendBroadCastSMS("SMS", model.Mobile, smsBody);

                        if (signInManager.IsSignedIn(User) && User.IsInRole("Admin"))
                        {
                            return RedirectToAction("ListUsers", "Administration");
                        }
                        await signInManager.SignInAsync(user, isPersistent: false);
                        return RedirectToAction("index", "home");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                else
                {

                }

                
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult SuperUserRegister()
        {
            var APART_CODE_LOCAL_VAR = HttpContext.Request.Cookies["COMCODE"];
            

            return View();
        }


       

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> SuperUserRegister(RegisterViewModel model)
        {
            ModelState.Clear();
            if (ModelState.IsValid)
            {
                if (model.TenantValue == "User")
                {
                    model.Tenant = false;
                    model.FlatOwner = model.Email;
                    model.IsLiving = true;
                }
                else if(model.TenantValue == "Tenant")
                {
                    model.Tenant = true;
                }
                else if (model.TenantValue == "Other")
                {
                    model.FlatOwner = null;
                    model.Flat_No = "-";
                    model.Tenant = true;
                    model.IsLiving = false;
                    model.IsRealFlatOwner = false;
                }


                    var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Mobile = model.Mobile,
                    NID = model.NID,
                    ETIN = model.ETIN,
                    PassportNo = model.PassportNo,
                    Per_Address = model.Per_Address,
                    pre_Address = model.pre_Address,
                    ProfilePicture= "no_picture.png",
                    UserRole = model.UserRole,
                    IsActive = true

                };
                var result = await userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    if (signInManager.IsSignedIn(User) && User.IsInRole("Admin"))
                    {
                        return RedirectToAction("ListUsers", "Administration");
                    }
                    await signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("index", "home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            return View(model);
        }



    }
}
