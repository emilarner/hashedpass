# hashedpass
Decentralized, storage less hash-based password management standard and program.

Version: 1.0.2
To Do:
 - Implement Argon2 parameter strings.

*hashedpass* is a program and library written in Python which seeks to standardize storage less, decentralized password management based off of hashing. In addition to *hashedpass* being a program/library, it also exists as a standard, written as a document; it can be found [here](https://github.com/emilarner/hashedpass/tree/main/docs). 

*hashedpass* is based off of SHA512 and Argon2. The master password, along with other parameters such as service/website and email/username, are first hashed with SHA512, then are fed into an expensive Argon2 hashing algorithm, with consistent salts and parameters. A lot more information regarding the specifics can be found in the standard, in the *docs/* folder.

The hope is that *hashedpass* can be used standalone to prevent ever losing a KeepassXC database, as all one requires is their common master password and the corresponding information for the account that the generated password is intended to go towards--if you remember the three parameters, you will always have your passwords. Alternatively, the more realistic approach is to use *hashedpass* in conjunction with something like KeepassXC: derive your passwords from *hashedpass*, store them into your KeepassXC database and use that primarily, using *hashedpass* as a backup if your KeepassXC database is ever lost. 


*hashedpass* can be used as a program with command-line arguments, though this is not encouraged: it requires the inclusion of your master password as a command-line argument, which would likely make its way into a shell history--a large security blunder. To explain the various arguments that *hashedpass* can take, we can take inspiration from its help menu, which can be accessed by issuing `-h/--help` as a command-line parameter:

    hashedpass.py - Make passwords via hashes with a master password, a decentralized password manager.
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


If one wants to use *hashedpass* as an interactive application, which will receive input from the terminal and calculate the desired passwords in a convenient fashion, with more features, then provide no command-line arguments to the program to achieve this.

As an interactive application, after inputting a master password for all subsequent password derivations, the program will exit on a timeout of 60 seconds if there is no activity, clearing and resetting the terminal. This will hopefully help to prevent accidental seeing of the generated passwords by others. 
