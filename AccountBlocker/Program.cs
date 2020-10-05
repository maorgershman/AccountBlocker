using Microsoft.Win32;
using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

class Program
{
    static void Main()
    {
        Console.Title = "AccountBlocker";

        var domain = LoadDomain();
        if (domain == null)
        {
            return;
        }

        var accountLockoutInformation = LoadAccountLockoutInformation();
        if (accountLockoutInformation == null)
        {
            return;
        }

        while (true)
        {
            Console.WriteLine("Enter a username to block: ");
            var username = Console.ReadLine();

            using (var context = LoadContext(domain))
            {
                if (context == null)
                {
                    continue;
                }

                using (var principal = FindUser(context, username))
                {
                    if (principal == null)
                    {
                        continue;
                    }

                    BlockUser(context, principal, username, accountLockoutInformation);
                }
            }
        }
    }

    private static string LoadDomain()
    {
        Console.WriteLine("Loading domain...");
        try
        {
            using (var domain = Domain.GetCurrentDomain())
            {
                Console.WriteLine($"Associated with domain: \"{domain.Name}\"\n");
                return domain.Name;
            }
        }
        catch (ActiveDirectoryOperationException)
        {
            Console.WriteLine("Error: Can't load domain!");
            Console.Read();
        }
        return null;
    }

    private static Tuple<int, int> LoadAccountLockoutInformation()
    {
        int maxDenials, lockoutDurationMinutes;

        try
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout"))
            {
                maxDenials = (int)key.GetValue("MaxDenials");
                lockoutDurationMinutes = (int)key.GetValue("ResetTime (mins)");

                key.Close();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Unable to read registry!");
            Console.WriteLine("({0}: {1})", ex.GetType(), ex.Message);
            Console.Read();
            return null;
        }

        if (maxDenials == 0)
        {
            Console.WriteLine("The system administrator has disabled account blocking after failing multiple authentication attempts!");
            Console.WriteLine("Note that because of that, the network might be vulnerable to easy password cracking using brute force.");
            Console.Read();
            return null;
        }

        return new Tuple<int, int>(maxDenials, lockoutDurationMinutes);
    }

    private static PrincipalContext LoadContext(string domain)
    {
        try
        {
            return new PrincipalContext(ContextType.Domain, domain);
        }
        catch (PrincipalOperationException)
        {
            Console.WriteLine("Error: No network connection!");
            return null;
        }
    }

    private static UserPrincipal FindUser(PrincipalContext context, string username)
    {
        try
        {
            var principal = UserPrincipal.FindByIdentity(context, username);

            if (principal != null)
            {
                return principal;
            }

            Console.WriteLine($"Error: Can't find user called \"{username}\"!");
        }
        catch (ArgumentException)
        {
            Console.WriteLine("Error: Bad username!");
        }
        catch (MultipleMatchesException)
        {
            Console.WriteLine("Error: Multiple users found!");
        }

        return null;
    }

    private static bool BlockUser(PrincipalContext context, UserPrincipal principal, string username, Tuple<int, int> accountLockoutInformation)
    {
        var maxDenials = accountLockoutInformation.Item1;
        var lockoutDurationMinutes = accountLockoutInformation.Item2;

        if (principal.IsAccountLockedOut())
        {
            Console.WriteLine($"\"{username}\" is already blocked!");
            return false;
        }

        for (int i = 0; i < maxDenials && !principal.IsAccountLockedOut(); i++)
        {
            context.ValidateCredentials(username, string.Empty);
        }

        if (principal.IsAccountLockedOut())
        {
            var lockoutTimeString = lockoutDurationMinutes == 0 ?
                "until an administrator unblocks him" :
                $"for {lockoutDurationMinutes} minutes";

            Console.WriteLine($"\"{username}\" has been successfully blocked {lockoutTimeString}!\n");
            return true;
        }
        else
        {
            Console.WriteLine($"Error: \"{username}\" can't be blocked after {maxDenials} attempts!\n");
            return false;
        }
    }
}