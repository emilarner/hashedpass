import sys
import os
import hashedpass
import blessed
import getpass
import readline
import time
import threading

import config

t = blessed.Terminal()

help_text = """
To generate your password, just type, in order (without brackets):

[service name] [username/email/id] [optional: constraint string]

For special commands, prefix them with an $--but you already knew that:
Special Commands:

[Dangerous, if you do not remember/record the parameters]
$argon2str [argon_string] - Set global argon2 parameters by string
$argon2 - Interactively configure argon2 parameters, then spit out the string parameters for saving.
"""

class HashedPassInteractive:
    "Interactive mode handler."

    def hello(self):
        "Interactive mode hello message."
        
        print(t.blue_bold("hashedpass - decentralized password manager based on hashes.\n"))

    def __init__(self):
        # Activate readline to make using this program easier.
        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode vi')

        self.timeout_thread: threading.Thread = None
        self.timingout = False
    
    def start(self):
        "Set everything up for interactive mode--make sure to call this!"
        
        # Display the hello text. 
        self.hello()

        # Securely obtain the master password.
        self.masterpassword = getpass.getpass("Enter your master password: ")
        
        # Start receiving commands
        self.main_loop()


    def main_loop(self):
        "Continuously obtain inputs for password derivation."

        while True:
            self.timingout = True
            self.timeout_thread = threading.Thread(target = self.timeout_thread)
            self.timeout_thread.start()

            command = input("hashedpass>")

            self.timingout = False

            if (command.startswith("$")):
                command = command.lstrip("$")

                if (command == "help"):
                    print(help_text)

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
                password = hashedpass.Password(self.masterpassword, service, id, hashedpass.Constraints())
            except hashedpass.Constraints.MalformedConstraint:
                sys.stderr.write("Error: the constraint string is malformed!\n")
                continue

            print(password.hash())


    def timeout(self, default_timeout = config.timeout):
        "To avoid the program from being open too long, close the program after a certain time."

        # Check if there has been activity one hundred times
        for i in range(100):
            # If there has been activity, this function is no longer required, so exit.
            if (not self.timingout):
                return
            
            # Wait 1/100 of the timeout time
            time.sleep(default_timeout / 100)

        # Exit and protect the user's password.
        sys.stderr.write("Timeout occured, program has exited. Now your secret password is long gone!\n")
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
            if (sys.argv[i] in ["-m", "--master-password", "-p", "--password"]):
                masterpassword = sys.argv[i + 1]

            if (sys.argv[i] in ["-s", "--service"]):
                service = sys.argv[i + 1]

            if (sys.argv[i] in ["-i", "--id", "-u", "--username", "-e", "--email"]):
                id = sys.argv[i + 1]

            if (sys.argv[i] in ["-a", "--argon2"]):
                argon2 = sys.argv[i + 1]

            if (sys.argv[i] in ["-c", "--constraints"]):
                constraints = sys.argv[i + 1]


    except IndexError as error:
        sys.stderr.write("Error: one of the arguments did not receive a value.\n")
        sys.exit(-1)


    # Check for null items.
    for item in [masterpassword, service, id]:
        if (item == None):
            sys.stderr.write("Error: a master password, service, and id/username/email are required.\n")
            sys.exit(-2)

    try:
        p = hashedpass.Password(masterpassword, service, id, 
                                hashedpass.Constraints(from_string = constraints))
    
    except hashedpass.Constraints.MalformedConstraint:
        sys.stderr.write("Error: the constraint string is malformed!\n")
        sys.exit(-3)

    print(p.hash())
    

    


if (__name__ == "__main__"):
    main()


