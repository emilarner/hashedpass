from email.errors import MalformedHeaderDefect
import os
import json
import sys
import hashlib
import passlib
import passlib.hash

# Default argon2 properties as defined in the protocol specification.
DEFAULT_MEM_SIZE = 262144 # in KiB
DEFAULT_ITERATIONS = 24
DEFAULT_PARALLELISM = 2
DEFAULT_KEYLENGTH = 32
DEFAULT_SALT = b"1" * 8

class Argon2Parameters:
    "A class organizing Argon2 parameters"

    class MalformedParameter(Exception):
        pass

    def __init__(self, memory, iterations, threads, size, salt):
        self.memory = memory
        self.iterations = iterations
        self.threads = threads
        self.size = size
        self.salt = salt

    # Argon2 parameter string in the format of:
    # memory:iterations:threads:size:salt

    def __str__(self) -> str:
        return f"{self.memory}:{self.iterations}:{self.threads}:{self.size}:{self.salt}"

    @staticmethod
    def from_string(string: str):
        "Initialize an Argon2Parameters object using the Argon2 parameter string. Does nothing if None"

        if (string == None):
            return Argon2Parameters(None, None, None, None, None)

        # Convert each element to an integer.
        strtokens = string.split(":")
        tokens = [int(x) for x in strtokens[0 - 3]]
        
        # Detect if the parameter is incorrect
        if (len(tokens) < 5):
            raise Argon2Parameters.MalformedParameter("Argon2 parameter string is incorrect")

        return Argon2Parameters(tokens[0], tokens[1], tokens[2], tokens[3], strtokens[4])




class Constraints:
    "Represents constraints and applies them in a consistent fashion."

    CAPITALS = list("QWERTYUIOPASDFGHJKLZXCVBNM")

    class MalformedConstraint(Exception):
        pass

    @staticmethod
    def from_string(constraint_str: str):
        "Return a Constraints object from its string representation. Does nothing if None"

        # Return default object if constraint_str == None
        if (constraint_str == None):
            return Constraints()




        # Make a dictionary corresponding the key names to the actual variables here
        key_to_value = {
            "l": 0,
            "ac": [],
            "oc": []
        }


        # Get each constraint
        constraints = constraint_str.split(";")

        # Go through them and then get their keys/values.
        for constraint in constraints:
            tokens = constraint.split("=")

            key = tokens[0].rstrip()

            print(key)

            # Only operate on valid keys
            if (key not in key_to_value):
                raise Constraints.MalformedConstraint(f"Key '{key}' is not a valid constraint.")

            value = tokens[1].lstrip()

            # Handle array types
            if (value.startswith("[")):
                value = value.lstrip("[").rstrip("]")
                value = value.split(",")

            key_to_value[key] = value


        # Return our beautiful constraint object
        return Constraints(
            length = key_to_value["l"], 
            ochars = key_to_value["oc"], 
            achars = key_to_value["ac"]
        )


            

    def __init__(self, length = 0, ochars = [], achars = []):
        self.length = int(length)
        self.ochars = ochars
        self.achars = achars


    def apply(self, seed: int, password: str):
        # Strings are immutable in Python, so let's make a list.
        result = list(password)

        # If there are length constraints, truncate the hash by it. 
        if (self.length != 0):
            result = result[0 : int(self.length)]

        # Position of where the number will go. 
        number_pos = seed % (len(result) - 1)
        if (number_pos == 0):
            number_pos = 1

        # Apply the random number clause between first char and second last character of digest.
        result[number_pos] = str(seed % 10)

        # Apply the random capital letter clause at the end of the Base64 digest.
        result[-1] = self.CAPITALS[seed % 26]

        # Keeps track of the index for AND characters.
        char_index = 1
        
        # The first character will be any of the OR required characters--if this is a constraint! 
        if (self.ochars != []):
            result[0] = self.ochars[seed % len(self.ochars)]

        # For every required character/symbol
        for achar in self.achars:
            # We do not want to overwrite the number 
            if (char_index == number_pos):
                char_index += 1

            # Set the required character after the first element (the OR required character)
            # then keep increasing the index after that
            result[char_index] = achar
            char_index += 1

        # Return the post-processed digest.
        return str("".join(result))


    def __str__(self):
        result = ""

        if (self.length != 0):
            result += f"l={self.length};"

        if (self.ochars != []):
            result += "oc=[" + ",".join(self.ochars) + "];"

        if (self.achars != []):
            result += "ac=[" + ",".join(self.achars) + "];"


        return result.rstrip(";")

        

            
class HashedPassword:
    "Represents the resulting hashed password, with its digest and its parameters."

    def __init__(self, digest, argon2_params, constraints):
        self.digest = digest
        self.argon2: Argon2Parameters = argon2_params
        self.constraints: Constraints = constraints

    def __str__(self) -> str:
        return f"{self.digest}:{str(self.argon2)}:{str(self.constraints)}"



class Password:
    "Represents a password that will be hashed to create a unique, secure one"

    def __init__(self, mpassword, service, id, constraints, 
                        iterations = DEFAULT_ITERATIONS,
                        memory = DEFAULT_MEM_SIZE,
                        threads = DEFAULT_PARALLELISM,
                        digestsize = DEFAULT_KEYLENGTH,
                        salt = DEFAULT_SALT):

        self.mpassword: str = mpassword
        self.service: str = service
        self.id: str = id
        self.constraints: Constraints = constraints

        self.iterations = iterations
        self.memory = memory
        self.threads = threads
        self.digestsize = digestsize
        self.salt = salt

    def hash(self) -> str:
        "Create a password from the information provided in this class."

        # This is the format for the hash as described in the standard.
        tbc = "{mpass}={service}={id}".format(
            mpass = self.mpassword,
            service = self.service.lower(),
            id = self.id.lower()
        )

        # Produce the sha512 hash, then feed that into a much more secure Argon2 hash.
        hashed = hashlib.sha512(tbc.encode()).digest()
        argon2i: passlib.hash.argon2 = passlib.hash.argon2.using(
            salt = self.salt,
            memory_cost = self.memory,
            digest_size = self.digestsize,
            max_threads = self.threads,
            time_cost = self.iterations
        )

        # Get the Base64 digest of the Argon2 hash, without any of the parameters.
        b64_hash = argon2i.hash(hashed).split("$")[-1]
        
        # Our seed value will be the ordinal value of the first character of the Base64 digest. 
        seed = ord(b64_hash[0])

        # Apply any constraints, if applicable, then return the final Base64 Argon2 digest.
        return self.constraints.apply(seed, b64_hash)


    def __str__(self):
        return self.hash()

