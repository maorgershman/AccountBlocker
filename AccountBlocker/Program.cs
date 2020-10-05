using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

class Program
{
    static void Main()
    {
        Console.Title = "AccountBlocker";

        string domain;
        try
        {
            Console.WriteLine("Loading domain...");
            domain = Domain.GetCurrentDomain().Name;
            Console.WriteLine($"Associated with domain: \"{domain}\"\n");
        }
        catch (ActiveDirectoryOperationException)
        {
            Console.WriteLine("Error: Can't load domain!");
            Console.ReadLine();
            return;
        }

        while (true)
        {
            Console.WriteLine("Enter a username to block: ");
            var username = Console.ReadLine();

            PrincipalContext context;
            try
            {
                context = new PrincipalContext(ContextType.Domain, domain);
            }
            catch (PrincipalOperationException)
            {
                Console.WriteLine("Error: No network connection!");
                continue;
            }

            UserPrincipal principal;
            try
            {
                principal = UserPrincipal.FindByIdentity(context, username);   
            }
            catch (ArgumentException)
            {
                Console.WriteLine("Error: Bad username!");
                continue;
            }
            catch (MultipleMatchesException)
            {
                Console.WriteLine("Error: Multiple users found!");
                continue;
            }

            if (principal == null)
            {
                Console.WriteLine($"Error: Can't find user called \"{username}\"!");
                continue;
            }

            if (principal.IsAccountLockedOut())
            {
                Console.WriteLine($"\"{username}\" is already blocked!");
                continue;
            }

            /*
                * Max value for failed authentication attempts is 999
                */ 
            for (int i = 0; i < 1000 && !principal.IsAccountLockedOut(); i++)
            {
                context.ValidateCredentials(username, string.Empty);
            }

            if (principal.IsAccountLockedOut())
            {
                Console.WriteLine($"\"{username}\" has been successfully blocked!\n");
            }
            else
            {
                Console.WriteLine($"\"{username}\" can't be blocked after 999 attempts!\n" + 
                    "Probably the network doesn't support protection from brute-force password cracking,\n" +
                    "and therefore doesn't block users when failing too many authentication attempts.");
                Console.ReadLine();
                return;
            }
        }
    }
}