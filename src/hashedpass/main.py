import sys
import os
import blessed
import getpass
import readline
import time
import threading

try:
    from hashedpass import hashedpass

except:
    import hashedpass

c_timeout = 60
c_showpass_timeout = 5
c_timeout_enabled_default = True

t = blessed.Terminal()

help_text = """
To generate your password, just type, in order (without brackets):

[service name] [username/email/id] [optional: constraint string]

For special commands, prefix them with an $--but you already knew that:
Special Commands:
$help - Display this menu.
$checkpass - Did you make a spelling mistake? Check your master password with this command.
$toggle_timeout - Toggle on/off the automatic timeout (by default, this is always on).

[Dangerous, if you do not remember/record the parameters]
$argon2str [argon_string] - Set global argon2 parameters by string
$argon2 - Interactively configure argon2 parameters, then spit out the string parameters for saving.
"""

arguments_text = """hashedpass.py - Make passwords via hashes with a master password, a decentralized password manager.
USAGE:

To use hashedpass in interactive mode (it gives prompts, etc), supply no arguments.

Using hashedpass with terminal arguments requires supplying the master password, service/website,
and username/email/id.

-m, --master-password  |        Supply the master password
-p, --password         |


-s, --service          |        Supply the website/service name
-w, --website          |        


-i, --id               |        Supply the id, username, or email.
-u, --username         |
-e, --email            |

-c, --constraint       |        Supply a constraint value, if applicable.
-a, --argon2           |        Supply custom argon2 parameters, if applicable.

"""

class HashedPassInteractive:
    "Interactive mode handler."

    def hello(self):
        "Interactive mode hello message."
        
        print(t.blue_bold("hashedpass - decentralized password manager based on hashes."))
        print(t.yellow_bold("Interactive Mode"))
        print(t.red_bold(
            f"This program will automatically exit and clear after {c_timeout} seconds of inactivity!\n"
        ))

    def __init__(self):
        # Activate readline to make using this program easier.
        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode vi')

        self.timeout_enabled = c_timeout_enabled_default
        self.timeout_thread: threading.Thread = None
        self.timingout = False
    
    def start(self):
        "Set everything up for interactive mode--make sure to call this!"
        
        # Display the hello text. 
        self.hello()

        # Securely obtain the master password.
        self.masterpassword = getpass.getpass("Enter your master password: ")
        print("To get help with commands and input, type $help")

        # Start receiving commands
        self.main_loop()


    def clear(self):
        os.system("clear && printf '\e[3J'")
        os.system("reset")

    def simple_clear(self):
        os.system("clear")

    def checkpass(self):
        print(f"Your master password is: {self.masterpassword}")
        print(t.bold_red("Clearing in: "))

        for i in reversed(range(c_showpass_timeout)):
            print(f"{i+1}")
            time.sleep(1)

        self.clear()

    def toggle_timeout(self):
        self.timeout_enabled = not self.timeout_enabled
        print("Timeout enabled" if self.timeout_enabled else "Timeout disabled")

    def main_loop(self):
        "Continuously obtain inputs for password derivation."

        while True:
            if (self.timeout_enabled):
                self.timingout = True
                self.timeout_thread = threading.Thread(target = self.timeout)
                self.timeout_thread.start()

            command = input("hashedpass>")

            self.timingout = False

            if (command.startswith("$")):
                command = command.lstrip("$")

                if (command == "help"):
                    print(help_text)

                elif (command == "showpass"):
                    self.checkpass()

                elif (command == "toggle_timeout"):
                    self.toggle_timeout

                elif (command == "clear"):
                    self.simple_clear()

                else:
                    sys.stderr.write(f"The command ${command} was not recognized. Seek $help?\n")

                continue

            args = command.split(" ")

            # Check for valid arguments
            if (len(args) < 2):
                sys.stderr.write("Error: you must provide a service name and an ID/email/username!\n")
                continue

            # Set up variables
            constraint_string = None
            service = args[0]
            id = args[1]

            # Get the constraint string, only if it was provided.
            if (len(args) > 2):
                constraint_string = args[2]

            # Get the password hash/digest
            try:
                password = hashedpass.Password(
                    self.masterpassword, 
                    service, 
                    id, 
                    hashedpass.Constraints.from_string(constraint_string)
                )
            except hashedpass.Constraints.MalformedConstraint:
                sys.stderr.write("Error: the constraint string is malformed!\n")
                continue

            print(password.hash())


    def timeout(self, default_timeout = c_timeout):
        "To avoid the program from being open too long, close the program after a certain time."

        # Check if there has been activity one hundred times
        for i in range(100):
            # If there has been activity, this function is no longer required, so exit.
            if (not self.timingout):
                return
            
            # Wait 1/100 of the timeout time
            time.sleep(default_timeout / 100)

        # Reset and clear the screen (UNIX only)
        self.clear()

        # Exit and protect the user's password.
        sys.stderr.write(t.red_bold(
            "Timeout occured, hashedpass has exited. Passwords should be gone now...\n"
        ))

        os._exit(-1)


def main():
    # No arguments mean interactive mode.
    if (len(sys.argv) < 2):
        i = HashedPassInteractive()
        i.start()

    # Initialize the variables to None/null.
    masterpassword = None
    service = None
    id = None
    argon2 = None
    constraints = None

    # Non-interactive mode: we are expecting command line arguments.
    try:
        for i in range(len(sys.argv)):
            if (sys.argv[i][0] == "-"):
                if (sys.argv[i] in ["-m", "--master-password", "-p", "--password"]):
                    masterpassword = sys.argv[i + 1]

                elif (sys.argv[i] in ["-s", "--service", "-w", "--website"]):
                    service = sys.argv[i + 1]

                elif (sys.argv[i] in ["-i", "--id", "-u", "--username", "-e", "--email"]):
                    id = sys.argv[i + 1]

                elif (sys.argv[i] in ["-a", "--argon2"]):
                    argon2 = sys.argv[i + 1]

                elif (sys.argv[i] in ["-c", "--constraints"]):
                    constraints = sys.argv[i + 1]

                elif (sys.argv[i] in ["-h", "--help"]):
                    print(arguments_text)
                    return

                else:
                    sys.stderr.write(f"'{sys.argv[i]}' is not a valid parameter. Exiting...\n")
                    sys.stderr.write("Try -h/--help ?\n")
                    sys.exit(-1)



    except IndexError as error:
        sys.stderr.write(f"Error: one of the arguments did not receive a value.\n")
        sys.exit(-1)


    # Check for null items.
    for item in [masterpassword, service, id]:
        if (item == None):
            sys.stderr.write("Error: a master password, service, and id/username/email are required.\n")
            sys.exit(-2)

    try:
        p = hashedpass.Password(masterpassword, service, id, 
                                hashedpass.Constraints.from_string(constraints))
    
    except hashedpass.Constraints.MalformedConstraint:
        sys.stderr.write("Error: the constraint string is malformed!\n")
        sys.exit(-3)

    print(p.hash())
    

    


if (__name__ == "__main__"):
    main()


