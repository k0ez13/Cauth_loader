using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.Security;

namespace CauthLoaderbyKoez
{
    public partial class Login : Form
    {
        public Login()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            Global.authInstance.init(); //init the global cauth instance xD
            InitializeComponent();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Register form = new Register(); //creates new form
            form.Show(); //show this form

        }

        private void button1_Click(object sender, EventArgs e)
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12; //bugs sometimes

            bool response = Global.authInstance.login(textBox1.Text, textBox2.Text); //login using the first and the second textbox //LOGIN //PASSWORD

            if (response)
            {
                Global.authInstance.log("Successfully logged in"); //log a message to the panel
                new Main().Show();
                this.Hide();
            }

        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }

        private void Login_Load(object sender, EventArgs e)
        {

        }
    }
}
