using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Diagnostics;
using ManualMapInjection.Injection;




namespace CauthLoaderbyKoez
{
    public partial class Main : Form
    {
        public Main()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            Global.authInstance.init(); //init the global cauth instance xD
            InitializeComponent();

            label1.Text = Global.authInstance.user_data.username;
            label2.Text = Global.authInstance.user_data.expires.ToString();
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void label2_Click(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; //bugs sometimes

            Process target = Process.GetProcessesByName("csgo").FirstOrDefault(); // csgo process check

            if (target != null) // check if csgo is open
            {
                try //try to do a function
                {
                    using (WebClient mac = new WebClient())
                    {
                        mac.Proxy = null;
                        mac.Headers.Add("agent_user", Global.authInstance.var("agent_user var")); //add user-agent headers, should be Mozilla
                        byte[] injecter = mac.DownloadData(Global.authInstance.var("download var")); //download the dll and save it to bytes, should be the download link
                        var injector = new ManualMapInjector(target) { AsyncInjection = true }; //initializing the injector
                        button1.Text = $"hmodule = 0x{injector.Inject(injecter).ToInt64():x8}"; //inject the dll
                        button1.Text = ("Success!!!");
                        Global.authInstance.log("injected successfully");
                        Application.Exit();
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception happened : " + ex); //check some exceptions
                    Application.Exit();
                }
            }
            else
            {
                MessageBox.Show("Please open CSGO"); //error open csgo
            }

        }
    }
}
