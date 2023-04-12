using FlatManagement.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FlatManagement.Utility
{
    public class GetFlowClass
    {
        private readonly MinistryDBContext _context;
        private IWebHostEnvironment webHostEnvironment;
        public IConfiguration _configuration;

        public GetFlowClass() { }
        public GetFlowClass(MinistryDBContext context, IWebHostEnvironment _webHostEnvironment, IConfiguration configuration)
        {
            _context = context;
            webHostEnvironment = _webHostEnvironment;
            _configuration = configuration;
        }

       
    }
}
