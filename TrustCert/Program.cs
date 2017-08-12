namespace TrustCert
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography.X509Certificates;
    using System.Windows.Forms;

    internal static class Program
    {
        private static X509Certificate2Collection FindCertsBySubject(StoreName storeName, StoreLocation storeLocation, string sFullSubject)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.OpenExistingOnly);
            store.Close();
            return store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, sFullSubject, false);
        }

        [STAThread]
        private static int Main(string[] sArgs)
        {
            Application.EnableVisualStyles();
            if (sArgs.Length < 1)
            {
                MessageBox.Show("Syntax:\r\n\tTrustCert.exe [-u] CertSubject", "Incorrect Parameters");
                return 1;
            }
            if ((sArgs.Length != 0) && (sArgs[0].StartsWith("/u", StringComparison.OrdinalIgnoreCase) || sArgs[0].StartsWith("-u", StringComparison.OrdinalIgnoreCase)))
            {
                bool flag = false;
                X509Certificate2Collection certificates = FindCertsBySubject(StoreName.Root, StoreLocation.LocalMachine, sArgs[1]);
                if (certificates.Count < 1)
                {
                    MessageBox.Show("The root certificate was not found in the Machine Root List.", "Note");
                }
                else if (!setMachineTrust(certificates[0], false))
                {
                    MessageBox.Show("Failed to remove the root certificate from the Machine Root List.", "TrustCert Failed");
                    return 4;
                }
                MessageBox.Show($"Removed Fiddler's root certificate from the Machine{flag ? " and User" : string.Empty} Root List.", "TrustCert success");
            }
            else
            {
                X509Certificate2Collection certificates2 = FindCertsBySubject(StoreName.Root, StoreLocation.CurrentUser, sArgs[0]);
                if (certificates2.Count < 1)
                {
                    MessageBox.Show("Failed to find the root certificate in User Root List.", "TrustCert Failed");
                    return 2;
                }
                if (!setMachineTrust(certificates2[0], true))
                {
                    MessageBox.Show("Failed to add the root certificate to the Machine Root List.", "TrustCert Failed");
                    return 3;
                }
                MessageBox.Show("Added Fiddler's root certificate to the Machine Root List.", "TrustCert Success");
            }
            return 0;
        }

        private static bool setMachineTrust(X509Certificate2 oRootCert, bool bEnableTrust)
        {
            if (oRootCert == null)
            {
                return false;
            }
            if (DialogResult.Yes != MessageBox.Show($"Please confirm that you wish to {bEnableTrust ? "ADD" : "REMOVE"} the following certificate {bEnableTrust ? "to" : "from"} your PC's Trusted Root List:

	{oRootCert.Subject.ToString().Replace(", ", "\r\n\t")}", "TrustCert Confirmation", MessageBoxButtons.YesNo))
            {
                return false;
            }
            try
            {
                X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                try
                {
                    if (bEnableTrust)
                    {
                        store.Add(oRootCert);
                    }
                    else
                    {
                        store.Remove(oRootCert);
                    }
                }
                finally
                {
                    store.Close();
                }
                return true;
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "TrustCert Failed");
                Trace.WriteLine("[FiddlerTrustCert] Failed to remove Machine roots: " + exception.Message);
                return false;
            }
        }
    }
}

