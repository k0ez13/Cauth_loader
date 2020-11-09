using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CauthLoaderbyKoez
{
    public partial class Register : Form
    {
        public Register()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            Global.authInstance.init(); //init the global cauth instance xD
            InitializeComponent();
        }

        private void Register_Load(object sender, EventArgs e)
        {


        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox3_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {

        }

        public bool response { get; set; }


        private void button1_Click(object sender, EventArgs e)
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12; //bugs sometimes

            if (checkBox1.Checked)
            {
                //The redeem arguments goes in the order: username, password, token
                response = Global.authInstance.activate(textBox1.Text, textBox4.Text); //redeem a token using textboxes /user, token
            }
            else
            {
                // The register arguments goes in the order: username, password, email, token
                response = Global.authInstance.register(textBox1.Text, textBox2.Text, textBox3.Text, textBox4.Text); //register using textboxes  //user, email, pass, token
            }
            if (response)
            {
                MessageBox.Show("Registered/Activated successfuly");
            }
            else
            {

            }
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked)
                button1.Text = "Activate"; //changing the text bcs yes lol
            else
                button1.Text = "Register";

        }
    }
}
